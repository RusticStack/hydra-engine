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
//! Plain-text rendering of results for `--text`. JSON is the default and the contract; text is a
//! convenience for people and for agents that want to read a listing directly.

use std::fmt::Write as _;

use serde_json::Value;

use crate::error::CliError;

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn rows(v: &Value, key: &str) -> Vec<Value> {
    v.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// A result as text. Commands without a dedicated layout print their JSON, indented.
#[must_use]
pub fn text(command: &str, result: &Value) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    match command {
        "decompile" => out.push_str(s(result, "c")),
        "disasm" => {
            for l in rows(result, "lines") {
                let address = s(&l, "address");
                if l.get("undefined").is_some() {
                    let _ = writeln!(out, "{address}  ??");
                } else if l.get("data").is_some() {
                    let _ = writeln!(out, "{address}  .{} {}", s(&l, "data"), s(&l, "text"));
                } else {
                    let _ = writeln!(out, "{address}  {:<20} {}", s(&l, "bytes"), s(&l, "text"));
                }
            }
        }
        "bytes" => out.push_str(&hexdump(s(result, "address"), s(result, "hex"))),
        "functions" => {
            for f in rows(result, "functions") {
                let size = f.get("size").map(Value::to_string).unwrap_or_default();
                let _ = writeln!(out, "{}  {size}  {}", s(&f, "address"), s(&f, "name"));
            }
        }
        "strings" => {
            for r in rows(result, "strings") {
                let _ = writeln!(out, "{}  {:?}", s(&r, "address"), s(&r, "value"));
            }
        }
        "imports" => {
            for r in rows(result, "imports") {
                let _ = writeln!(out, "{}!{}", s(&r, "library"), s(&r, "name"));
            }
        }
        "xrefs" | "callers" => {
            let key = if command == "xrefs" {
                "references"
            } else {
                "callers"
            };
            for r in rows(result, key) {
                let _ = writeln!(
                    out,
                    "{} -> {}  {}  {}",
                    s(&r, "from"),
                    s(&r, "to"),
                    s(&r, "type"),
                    s(&r, "function")
                );
            }
        }
        "callees" => {
            for r in rows(result, "callees") {
                let _ = writeln!(out, "{}  {}", s(&r, "entry"), s(&r, "name"));
            }
        }
        "search" => {
            for r in rows(result, "matches") {
                let _ = writeln!(
                    out,
                    "{}  {}  {}",
                    s(&r, "address"),
                    s(&r, "block"),
                    s(&r, "function")
                );
            }
        }
        _ => {
            out.push_str(&serde_json::to_string_pretty(result).unwrap_or_default());
            out.push('\n');
        }
    }
    if result.get("truncated") == Some(&Value::Bool(true)) {
        out.push_str("(truncated; use --limit/--offset)\n");
    }
    out
}

/// Sixteen bytes to a line, each line led by its address.
fn hexdump(address: &str, hex: &str) -> String {
    let start = u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap_or(0);
    let mut out = String::new();
    for (line_no, line) in hex.as_bytes().chunks(32).enumerate() {
        let spaced: Vec<&str> = line
            .chunks(2)
            .map(|b| std::str::from_utf8(b).unwrap_or("??"))
            .collect();
        let offset = u64::try_from(line_no).unwrap_or(0) * 16;
        let _ = writeln!(
            out,
            "{:#x}  {}",
            start.saturating_add(offset),
            spaced.join(" ")
        );
    }
    out
}

/// A failure as text, for stderr.
#[must_use]
pub fn error_text(e: &CliError) -> String {
    let mut out = format!("hydra: {}: {}\n", e.code, e.message);
    if let Some(h) = &e.hint {
        let _ = writeln!(out, "hint: {h}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disassembly_prints_one_instruction_per_line() {
        let r =
            json!({"lines": [{"address": "0x1000", "bytes": "4883ec28", "text": "SUB RSP,0x28"}]});
        assert_eq!(
            text("disasm", &r),
            "0x1000  4883ec28             SUB RSP,0x28\n"
        );
    }

    #[test]
    fn bytes_are_dumped_sixteen_to_a_line() {
        let r = json!({"address": "0x10", "hex": "00".repeat(20)});
        let t = text("bytes", &r);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0x10  00 00"), "{t}");
        assert!(lines[1].starts_with("0x20  00 00 00 00"), "{t}");
    }

    #[test]
    fn truncation_is_called_out() {
        let r = json!({"strings": [], "truncated": true});
        assert!(text("strings", &r).contains("truncated"));
    }

    #[test]
    fn unknown_commands_fall_back_to_indented_json() {
        assert!(text("info", &json!({"a": 1})).contains("\"a\": 1"));
    }
}
