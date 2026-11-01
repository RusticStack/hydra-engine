//! The raw segment: append-only lines `crc-hex8 SP json LF`, CRC-32 (IEEE) of the JSON bytes,
//! identical to `durable.AppendLog`. Each record carries `n`, `prev` and `hash` (SHA-256 of the
//! canonical JSON without `hash`), so the segment is hash-chained from a per-segment genesis.
//! A reader sees the valid prefix; a torn tail (a final line without LF or with a bad CRC) is
//! reported and ignored; a bad line followed by more data is corruption.

use crate::canon;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The genesis input; the genesis hash is SHA-256 of this text followed by the segment id.
pub const GENESIS: &str = "hydra.trace.segment/1\n";

/// SHA-256 hex of the segment genesis.
pub fn genesis_hash(segment: &str) -> String {
    hex(&Sha256::digest(format!("{GENESIS}{segment}").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The chain hash of `record`: SHA-256 of its canonical JSON without the `hash` field.
pub fn record_hash(record: &Map<String, Value>) -> Result<String, canon::NotCanonical> {
    let mut body = record.clone();
    body.remove("hash");
    Ok(hex(&Sha256::digest(canon::to_vec(&Value::Object(body))?)))
}

/// Frame `record` (which already has `n`, `prev` and `hash`) as one line.
pub fn frame(record: &Map<String, Value>) -> Result<Vec<u8>, canon::NotCanonical> {
    let body = canon::to_vec(&Value::Object(record.clone()))?;
    let mut line = format!("{:08x} ", crc32fast::hash(&body)).into_bytes();
    line.extend_from_slice(&body);
    line.push(b'\n');
    Ok(line)
}

/// Builds a chained segment (the writer side used by the generator, importers and tests; live
/// writers append the same bytes).
pub struct Chain {
    head: String,
    n: u64,
}

impl Chain {
    pub fn new(segment: &str) -> Self {
        Self {
            head: genesis_hash(segment),
            n: 0,
        }
    }

    /// Chain `record`: set `n`, `prev`, `hash`, and return the framed line.
    pub fn push(&mut self, mut record: Map<String, Value>) -> Result<Vec<u8>, canon::NotCanonical> {
        record.insert("n".into(), Value::from(self.n));
        record.insert("prev".into(), Value::from(self.head.clone()));
        let hash = record_hash(&record)?;
        record.insert("hash".into(), Value::from(hash.clone()));
        let line = frame(&record)?;
        self.head = hash;
        self.n += 1;
        Ok(line)
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn count(&self) -> u64 {
        self.n
    }
}

/// Why a scan stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Damage {
    /// The final bytes are not a complete valid line (a writer died mid-append). Ignored.
    TornTail { offset: usize, bytes: usize },
    /// A bad line is followed by more data: the segment is corrupt at `offset`.
    Corrupt { offset: usize, line: usize },
    /// A valid line breaks the chain or the numbering.
    ChainBreak {
        offset: usize,
        n: u64,
        reason: &'static str,
    },
}

/// The result of reading a segment.
#[derive(Debug, Default)]
pub struct Scan {
    pub records: Vec<Map<String, Value>>,
    /// Bytes of the valid, chain-verified prefix.
    pub valid_end: usize,
    pub size: usize,
    pub head: String,
    pub damage: Option<Damage>,
}

impl Scan {
    /// True when every byte was a valid chained record.
    pub fn is_clean(&self) -> bool {
        self.damage.is_none() && self.valid_end == self.size
    }
}

fn parse_line(line: &[u8]) -> Option<Map<String, Value>> {
    if line.len() < 10 || line[8] != b' ' {
        return None;
    }
    let crc = u32::from_str_radix(std::str::from_utf8(&line[..8]).ok()?, 16).ok()?;
    let body = &line[9..];
    if crc32fast::hash(body) != crc {
        return None;
    }
    match serde_json::from_slice::<Value>(body).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Read and verify a whole segment. `segment` is the id its genesis was derived from.
pub fn scan(data: &[u8], segment: &str) -> Scan {
    let mut out = Scan {
        size: data.len(),
        head: genesis_hash(segment),
        ..Scan::default()
    };
    let mut cursor = 0usize;
    let mut line_no = 0usize;
    while cursor < data.len() {
        let Some(rel) = data[cursor..].iter().position(|&b| b == b'\n') else {
            out.damage = Some(Damage::TornTail {
                offset: cursor,
                bytes: data.len() - cursor,
            });
            return out;
        };
        let end = cursor + rel;
        line_no += 1;
        let Some(record) = parse_line(&data[cursor..end]) else {
            out.damage = Some(if end + 1 >= data.len() {
                Damage::TornTail {
                    offset: cursor,
                    bytes: data.len() - cursor,
                }
            } else {
                Damage::Corrupt {
                    offset: cursor,
                    line: line_no,
                }
            });
            return out;
        };
        let n = record.get("n").and_then(Value::as_u64);
        if n != Some(out.records.len() as u64) {
            out.damage = Some(Damage::ChainBreak {
                offset: cursor,
                n: n.unwrap_or(u64::MAX),
                reason: "numbering",
            });
            return out;
        }
        if record.get("prev").and_then(Value::as_str) != Some(out.head.as_str()) {
            out.damage = Some(Damage::ChainBreak {
                offset: cursor,
                n: n.unwrap_or(0),
                reason: "prev",
            });
            return out;
        }
        let hash = record_hash(&record).ok();
        if hash.as_deref() != record.get("hash").and_then(Value::as_str) {
            out.damage = Some(Damage::ChainBreak {
                offset: cursor,
                n: n.unwrap_or(0),
                reason: "hash",
            });
            return out;
        }
        out.head = hash.unwrap_or_default();
        out.records.push(record);
        cursor = end + 1;
        out.valid_end = cursor;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(kind: &str) -> Map<String, Value> {
        json!({"kind": kind, "t": 5}).as_object().unwrap().clone()
    }

    fn segment(count: usize) -> Vec<u8> {
        let mut chain = Chain::new("s1");
        (0..count)
            .flat_map(|i| chain.push(rec(&format!("k{i}"))).unwrap())
            .collect()
    }

    #[test]
    fn clean_segment_verifies() {
        let data = segment(5);
        let result = scan(&data, "s1");
        assert!(result.is_clean());
        assert_eq!(result.records.len(), 5);
    }

    #[test]
    fn torn_tail_is_reported_and_prefix_kept() {
        let mut data = segment(3);
        let full = data.len();
        data.extend_from_slice(b"deadbeef {\"n\":3");
        let result = scan(&data, "s1");
        assert_eq!(result.records.len(), 3);
        assert_eq!(result.valid_end, full);
        assert!(matches!(result.damage, Some(Damage::TornTail { .. })));
    }

    #[test]
    fn flipped_byte_in_the_middle_is_corruption() {
        let mut data = segment(4);
        data[20] ^= 0x01;
        let result = scan(&data, "s1");
        assert!(matches!(result.damage, Some(Damage::Corrupt { .. })));
        assert!(result.records.is_empty());
    }

    #[test]
    fn wrong_segment_id_breaks_the_chain_at_the_start() {
        let data = segment(2);
        let result = scan(&data, "other");
        assert!(matches!(
            result.damage,
            Some(Damage::ChainBreak { reason: "prev", .. })
        ));
    }

    #[test]
    fn empty_segment_is_clean_and_empty() {
        let result = scan(b"", "s1");
        assert!(result.is_clean() && result.records.is_empty());
    }
}
