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
//! Request fields read the way the Java daemon's `Json` helper reads them, with the same
//! `bad_request` messages. Where Gson's reading of a value cannot be reproduced exactly (a
//! non-ASCII digit, a number that wraps) the accessor refuses instead.

use crate::error::{Failure, Reason, SessionError, refuse};
use crate::json::Json;

/// The default `wait` of a request in milliseconds (`Requests.DEFAULT_WAIT_MS`).
pub const DEFAULT_WAIT_MS: i64 = 10_000;

/// The longest label a `client` or `harness` field may carry (`Caller.MAX_LABEL`).
const MAX_LABEL: usize = 128;

/// A parsed request object.
#[derive(Debug, Clone)]
pub struct Request {
    obj: Json,
}

impl Request {
    /// Wraps a parsed JSON object.
    #[must_use]
    pub fn new(obj: Json) -> Self {
        Self { obj }
    }

    /// The raw member, `null` included.
    #[must_use]
    pub fn raw(&self, key: &str) -> Option<&Json> {
        self.obj.get(key)
    }

    /// The names of all members, in request order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.obj
            .members()
            .unwrap_or_default()
            .iter()
            .map(|(k, _)| k.as_str())
    }

    /// `Json.has`: present and not `null`.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        !matches!(self.obj.get(key), None | Some(Json::Null))
    }

    /// `Json.str(req, k)`: a required scalar read as text.
    ///
    /// # Errors
    ///
    /// `bad_request` when the field is missing or not a scalar.
    pub fn str(&self, key: &str) -> Result<String, Failure> {
        if !self.has(key) {
            return Err(SessionError::bad_request(format!("missing field: {key}")).into());
        }
        self.scalar_text(key)
    }

    /// `Json.str(req, k, dflt)`.
    ///
    /// # Errors
    ///
    /// `bad_request` when the field is present and not a scalar.
    pub fn str_opt(&self, key: &str) -> Result<Option<String>, Failure> {
        if self.has(key) {
            self.scalar_text(key).map(Some)
        } else {
            Ok(None)
        }
    }

    fn scalar_text(&self, key: &str) -> Result<String, Failure> {
        match self.obj.get(key) {
            Some(Json::Str(s)) => Ok(s.clone()),
            Some(Json::Num(n)) => Ok(n.clone()),
            Some(Json::Bool(b)) => Ok(b.to_string()),
            _ => Err(SessionError::bad_request(format!("{key} must be a scalar")).into()),
        }
    }

    /// `Json.bool(req, k, dflt)`: the boolean, or `None` when the field is absent or `null` (the
    /// caller applies its default).
    ///
    /// # Errors
    ///
    /// `bad_request` when the field is present and not a boolean.
    pub fn bool_opt(&self, key: &str) -> Result<Option<bool>, Failure> {
        if !self.has(key) {
            return Ok(None);
        }
        match self.obj.get(key) {
            Some(Json::Bool(b)) => Ok(Some(*b)),
            Some(Json::Str(_) | Json::Num(_)) => {
                Err(SessionError::bad_request(format!("{key} must be true or false")).into())
            }
            _ => Err(SessionError::bad_request(format!("{key} must be a scalar")).into()),
        }
    }

    /// `Json.num(req, k, dflt, min, max)`: `getAsLong` and the range check.
    ///
    /// # Errors
    ///
    /// `bad_request` as Java words it; a refusal for a value Java reads in a way this does not
    /// reproduce (a huge decimal, a non-ASCII digit).
    pub fn num(&self, key: &str, default: i64, min: i64, max: i64) -> Result<i64, Failure> {
        if !self.has(key) {
            return Ok(default);
        }
        let not_a_number = || SessionError::bad_request(format!("{key} must be a number"));
        let v = match self.obj.get(key) {
            Some(Json::Num(text)) => match long_of_number(text) {
                LongValue::Ok(v) => v,
                LongValue::Inexact => {
                    return Err(refuse(
                        Reason::InexactValue,
                        format!(
                            "{key}: the number {text} is not one this daemon reads as Java does"
                        ),
                    ));
                }
            },
            Some(Json::Str(s)) => {
                if !s.is_ascii() {
                    return Err(refuse(
                        Reason::InexactValue,
                        format!("{key}: a non-ASCII text where a number is read"),
                    ));
                }
                s.parse::<i64>().map_err(|_| not_a_number())?
            }
            Some(Json::Bool(_)) => return Err(not_a_number().into()),
            _ => return Err(SessionError::bad_request(format!("{key} must be a scalar")).into()),
        };
        if v < min || v > max {
            return Err(SessionError::bad_request(format!(
                "{key} must be between {min} and {max}"
            ))
            .into());
        }
        Ok(v)
    }

    /// `Requests.waitMs`: `wait` as milliseconds; a boolean means the default.
    ///
    /// # Errors
    ///
    /// As [`Request::num`].
    pub fn wait_ms(&self) -> Result<i64, Failure> {
        if matches!(self.obj.get("wait"), Some(Json::Bool(_))) {
            return Ok(DEFAULT_WAIT_MS);
        }
        self.num("wait", DEFAULT_WAIT_MS, 0, 86_400_000)
    }

    /// `Caller.field`: a `client` or `harness` label.
    ///
    /// # Errors
    ///
    /// `bad_request` when the label is not a string or is too long.
    pub fn label(&self, key: &str) -> Result<Option<String>, SessionError> {
        match self.obj.get(key) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::Str(s)) => {
                let s = java_strip(s);
                if s.chars().map(char::len_utf16).sum::<usize>() > MAX_LABEL {
                    return Err(SessionError::bad_request(format!(
                        "\"{key}\" is longer than {MAX_LABEL} characters"
                    )));
                }
                Ok(if s.is_empty() {
                    None
                } else {
                    Some(s.to_owned())
                })
            }
            Some(_) => Err(SessionError::bad_request(format!(
                "\"{key}\" is a label: a string"
            ))),
        }
    }
}

/// `String.strip()`: removes leading and trailing white space as `Character.isWhitespace` sees it
/// (for the characters that occur in labels this is Unicode `White_Space` without the no-break
/// spaces).
fn java_strip(s: &str) -> &str {
    s.trim_matches(|c: char| {
        c.is_whitespace() && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}')
            || matches!(c, '\u{1c}'..='\u{1f}')
    })
}

enum LongValue {
    Ok(i64),
    Inexact,
}

/// `LazilyParsedNumber.longValue()`: `Long.parseLong`, else `BigDecimal.longValue()` (the integer
/// part, truncated toward zero). Values outside `i64` wrap in Java; they are `Inexact` here.
fn long_of_number(text: &str) -> LongValue {
    if let Ok(v) = text.parse::<i64>() {
        return LongValue::Ok(v);
    }
    let (neg, rest) = text.strip_prefix('-').map_or((false, text), |r| (true, r));
    let (mantissa, exp) = match rest.split_once(['e', 'E']) {
        Some((m, e)) => match e.parse::<i32>() {
            Ok(e) => (m, e),
            Err(_) => return LongValue::Inexact,
        },
        None => (rest, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = String::from(int_part);
    digits.push_str(frac_part);
    let Ok(frac_len) = i32::try_from(frac_part.len()) else {
        return LongValue::Inexact;
    };
    // value = digits * 10^(exp - frac_len)
    let shift = exp - frac_len;
    let integer_digits: String = if shift >= 0 {
        let Ok(zeros) = usize::try_from(shift) else {
            return LongValue::Inexact;
        };
        if zeros > 40 {
            return LongValue::Inexact;
        }
        let mut d = digits;
        d.push_str(&"0".repeat(zeros));
        d
    } else {
        let Ok(cut) = usize::try_from(-shift) else {
            return LongValue::Inexact;
        };
        if cut >= digits.len() {
            String::from("0")
        } else {
            digits[..digits.len() - cut].to_owned()
        }
    };
    let trimmed = integer_digits.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    match trimmed.parse::<i64>() {
        Ok(v) => LongValue::Ok(if neg { -v } else { v }),
        Err(_) => LongValue::Inexact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn req(text: &str) -> Request {
        Request::new(parse(text).expect("test json"))
    }

    fn msg(f: Failure) -> String {
        match f {
            Failure::Error(e) => format!("{}: {}", e.code, e.message),
            Failure::Refuse(r) => format!("refused {:?}", r.reason),
        }
    }

    #[test]
    fn num_reads_like_gson() {
        let r = req(
            r#"{"a":"7","b":2.9,"c":-1e1,"d":"many","e":true,"f":99999999999999999999,"g":[1]}"#,
        );
        assert_eq!(
            r.num("a", 0, 0, 10).expect("string 7"),
            7,
            "a numeric string"
        );
        assert_eq!(
            r.num("b", 0, 0, 10).expect("2.9"),
            2,
            "truncated toward zero"
        );
        assert_eq!(r.num("c", 0, -20, 10).expect("-1e1"), -10, "an exponent");
        assert_eq!(
            msg(r.num("d", 0, 0, 10).unwrap_err()),
            "bad_request: d must be a number"
        );
        assert_eq!(
            msg(r.num("e", 0, 0, 10).unwrap_err()),
            "bad_request: e must be a number"
        );
        assert!(
            msg(r.num("f", 0, 0, 10).unwrap_err()).starts_with("refused"),
            "wraps in Java"
        );
        assert_eq!(
            msg(r.num("g", 0, 0, 10).unwrap_err()),
            "bad_request: g must be a scalar"
        );
        assert_eq!(
            msg(r.num("a", 0, 8, 10).unwrap_err()),
            "bad_request: a must be between 8 and 10"
        );
        assert_eq!(
            r.num("zz", 5, 0, 10).expect("default"),
            5,
            "absent is the default"
        );
    }

    #[test]
    fn wait_accepts_a_boolean() {
        assert_eq!(
            req(r#"{"wait":true}"#).wait_ms().expect("bool"),
            DEFAULT_WAIT_MS,
            "bool"
        );
        assert_eq!(req(r#"{"wait":5}"#).wait_ms().expect("num"), 5, "number");
        assert_eq!(
            msg(req(r#"{"wait":"x"}"#).wait_ms().unwrap_err()),
            "bad_request: wait must be a number",
            "text"
        );
    }

    #[test]
    fn labels_follow_caller_field() {
        let r = req(r#"{"client":" a b ","harness":5,"x":""}"#);
        assert_eq!(
            r.label("client").expect("label").as_deref(),
            Some("a b"),
            "stripped"
        );
        assert_eq!(
            r.label("harness").unwrap_err().message,
            "\"harness\" is a label: a string",
            "not a string"
        );
        assert_eq!(r.label("x").expect("empty"), None, "empty is none");
    }

    #[test]
    fn str_reads_scalars_as_text() {
        let r = req(r#"{"a":1e3,"b":true,"c":{}}"#);
        assert_eq!(r.str("a").expect("number"), "1e3", "number text as written");
        assert_eq!(r.str("b").expect("bool"), "true", "bool text");
        assert_eq!(
            msg(r.str("c").unwrap_err()),
            "bad_request: c must be a scalar",
            "object"
        );
        assert_eq!(
            msg(r.str("d").unwrap_err()),
            "bad_request: missing field: d",
            "missing"
        );
    }
}
