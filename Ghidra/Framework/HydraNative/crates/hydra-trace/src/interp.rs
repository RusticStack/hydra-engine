//! Interpretations (TRACE-1 section 10). An observation's bytes are immutable; what they mean is
//! an interpretation revision: a codec (layout) applied over a context interval of the trace,
//! recording the codec and schema hashes and, per decoded field, the byte range it came from.
//! A corrected codec or a newly learned layout is a new revision. Old revisions stay readable
//! and queries can pin one.

use crate::canon;
use crate::store::{Error, Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub offset: u32,
    pub len: u32,
    /// `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64` or `hex`.
    #[serde(rename = "type")]
    pub ty: String,
    /// `le` (default) or `be`.
    #[serde(default)]
    pub endian: Option<String>,
}

/// A layout of a byte payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Codec {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

fn sha(value: &Value) -> String {
    let bytes = canon::to_vec(value).unwrap_or_default();
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Codec {
    /// Hash of the whole layout: offsets and sizes included.
    pub fn codec_hash(&self) -> String {
        sha(&json!({
            "name": self.name,
            "fields": self.fields.iter().map(|f| json!({
                "name": f.name, "offset": f.offset, "len": f.len, "type": f.ty,
                "endian": f.endian.clone().unwrap_or_else(|| "le".into()),
            })).collect::<Vec<_>>(),
        }))
    }

    /// Hash of the logical schema: field names and types only, so two layouts of the same
    /// message share it.
    pub fn schema_hash(&self) -> String {
        let mut fields: Vec<(&str, &str)> = self
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.ty.as_str()))
            .collect();
        fields.sort_unstable();
        sha(&json!({"name": self.name, "fields": fields}))
    }
}

/// A codec in force over `from_seq ..= to_seq` (open ended when `None`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Context {
    pub from_seq: i64,
    pub to_seq: Option<i64>,
    pub codec: Codec,
}

/// One decoded field with its provenance.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Decoded {
    pub field: String,
    pub value: Value,
    pub byte_off: Option<u32>,
    pub byte_len: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ReprocessStats {
    pub revision: i64,
    pub decoded: u64,
    pub no_context: u64,
    pub short_payload: u64,
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn decode_field(f: &FieldDef, bytes: &[u8]) -> Option<Value> {
    let (off, len) = (f.offset as usize, f.len as usize);
    let raw = bytes.get(off..off.checked_add(len)?)?;
    if f.ty == "hex" {
        return Some(Value::String(
            raw.iter().map(|b| format!("{b:02x}")).collect(),
        ));
    }
    let width = match f.ty.as_str() {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" => 4,
        "u64" | "i64" => 8,
        _ => return None,
    };
    if len != width {
        return None;
    }
    let mut buf = [0u8; 8];
    if f.endian.as_deref() == Some("be") {
        buf[8 - width..].copy_from_slice(raw);
        let v = u64::from_be_bytes(buf);
        Some(signed(&f.ty, v, width))
    } else {
        buf[..width].copy_from_slice(raw);
        let v = u64::from_le_bytes(buf);
        Some(signed(&f.ty, v, width))
    }
}

fn signed(ty: &str, v: u64, width: usize) -> Value {
    if ty.starts_with('i') {
        let shift = 64 - 8 * width as u32;
        json!(((v << shift) as i64) >> shift)
    } else {
        json!(v)
    }
}

/// The contexts a trace declares itself: each `core.marker` event with a `layout` payload field
/// starts the codec of that name, until the next such marker. `codecs` maps layout names to
/// codecs; a marker naming an unknown layout leaves its interval without a codec (the events in
/// it stay undecoded and are counted).
pub fn contexts_from_markers(
    store: &Store,
    codecs: &BTreeMap<String, Codec>,
) -> Result<Vec<Context>> {
    let mut stmt = store.conn().prepare(
        "SELECT seq, payload FROM events WHERE kind='core.marker' AND payload LIKE '%\"layout\"%' ORDER BY seq",
    )?;
    let marks: Vec<(i64, String)> = stmt
        .query_map([], |r| {
            let payload: String = r.get(1)?;
            let layout = serde_json::from_str::<Value>(&payload)
                .ok()
                .and_then(|v| v.get("layout").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            Ok((r.get(0)?, layout))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut out = Vec::new();
    for (i, (seq, layout)) in marks.iter().enumerate() {
        let Some(codec) = codecs.get(layout) else {
            continue;
        };
        out.push(Context {
            from_seq: *seq,
            to_seq: marks.get(i + 1).map(|(next, _)| next - 1),
            codec: codec.clone(),
        });
    }
    Ok(out)
}

/// Decode the `bytes` (hex string) payload field of every event of `kinds` under `contexts`, as a
/// new interpretation revision. Earlier revisions are left as they were.
pub fn reprocess(
    store: &mut Store,
    contexts: &[Context],
    kinds: &[String],
    note: &str,
) -> Result<ReprocessStats> {
    if contexts.is_empty() {
        return Err(Error::Refused("no context to interpret under".into()));
    }
    let combined = json!(
        contexts
            .iter()
            .map(|c| json!({"from": c.from_seq, "to": c.to_seq, "codec": c.codec.codec_hash()}))
            .collect::<Vec<_>>()
    );
    let schema = sha(&json!(
        contexts
            .iter()
            .map(|c| c.codec.schema_hash())
            .collect::<std::collections::BTreeSet<_>>()
    ));
    let from = contexts.iter().map(|c| c.from_seq).min();
    let to = if contexts.iter().any(|c| c.to_seq.is_none()) {
        None
    } else {
        contexts.iter().filter_map(|c| c.to_seq).max()
    };
    let tx = store.conn_mut().transaction()?;
    let parent: Option<i64> = tx
        .query_row(
            "SELECT MAX(rev) FROM interpretations WHERE kind='decode'",
            [],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let rev: i64 = tx.query_row(
        "SELECT COALESCE(MAX(rev),0)+1 FROM interpretations",
        [],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO interpretations(rev,kind,parent,symbol_revision,codec_hash,schema_hash,context_from,context_to,note)
         VALUES(?1,'decode',?2,NULL,?3,?4,?5,?6,?7)",
        params![rev, parent, sha(&combined), schema, from, to, note],
    )?;
    let mut stats = ReprocessStats {
        revision: rev,
        ..ReprocessStats::default()
    };
    {
        let mut sql =
            String::from("SELECT seq, payload FROM events WHERE payload LIKE '%\"bytes\"%'");
        if !kinds.is_empty() {
            sql.push_str(&format!(
                " AND kind IN ({})",
                vec!["?"; kinds.len()].join(",")
            ));
        }
        sql.push_str(" ORDER BY seq");
        let mut read = tx.prepare(&sql)?;
        let mut write = tx.prepare_cached(
            "INSERT INTO interp_fields(interp,seq,field,value,byte_off,byte_len) VALUES(?1,?2,?3,?4,?5,?6)",
        )?;
        let mut rows = read.query(rusqlite::params_from_iter(kinds.iter()))?;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let payload: String = row.get(1)?;
            let Some(bytes) = serde_json::from_str::<Value>(&payload)
                .ok()
                .and_then(|v| v.get("bytes").and_then(Value::as_str).and_then(parse_hex))
            else {
                continue;
            };
            let Some(ctx) = contexts
                .iter()
                .rev()
                .find(|c| c.from_seq <= seq && c.to_seq.is_none_or(|t| seq <= t))
            else {
                stats.no_context += 1;
                continue;
            };
            let mut short = false;
            for f in &ctx.codec.fields {
                match decode_field(f, &bytes) {
                    Some(v) => {
                        write.execute(params![rev, seq, f.name, v.to_string(), f.offset, f.len])?;
                    }
                    None => short = true,
                }
            }
            if short {
                write.execute(params![
                    rev,
                    seq,
                    "_error",
                    "\"short-payload\"",
                    None::<i64>,
                    None::<i64>
                ])?;
                stats.short_payload += 1;
            } else {
                stats.decoded += 1;
            }
        }
    }
    tx.execute(
        "UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='revision'",
        [],
    )?;
    tx.commit()?;
    Ok(stats)
}

/// The decode revisions, oldest first: `(rev, parent, codec_hash, schema_hash, note)`.
pub fn revisions(store: &Store) -> Result<Vec<(i64, Option<i64>, String, String, String)>> {
    let mut stmt = store.conn().prepare(
        "SELECT rev,parent,COALESCE(codec_hash,''),COALESCE(schema_hash,''),COALESCE(note,'') FROM interpretations WHERE kind='decode' ORDER BY rev",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

/// The fields of `seq` under revision `rev` (the latest decode revision when `None`).
pub fn decoded(store: &Store, seq: i64, rev: Option<i64>) -> Result<Vec<Decoded>> {
    let rev = match rev {
        Some(r) => r,
        None => match revisions(store)?.last() {
            Some(r) => r.0,
            None => return Ok(Vec::new()),
        },
    };
    let mut stmt = store.conn().prepare(
        "SELECT field,value,byte_off,byte_len FROM interp_fields WHERE interp=?1 AND seq=?2 ORDER BY field",
    )?;
    let rows = stmt.query_map(params![rev, seq], |r| {
        let value: String = r.get(1)?;
        Ok(Decoded {
            field: r.get(0)?,
            value: serde_json::from_str(&value).unwrap_or(Value::Null),
            byte_off: r.get(2)?,
            byte_len: r.get(3)?,
        })
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_tests::{ev, records};

    fn field(name: &str, offset: u32, len: u32, ty: &str) -> FieldDef {
        FieldDef {
            name: name.into(),
            offset,
            len,
            ty: ty.into(),
            endian: None,
        }
    }

    /// Layout A: id u16 at 0, hp u16 at 2. Layout B (negotiated later): hp u32 at 0, id u16 at 4.
    fn codecs() -> BTreeMap<String, Codec> {
        BTreeMap::from([
            (
                "A".to_string(),
                Codec {
                    name: "msg".into(),
                    fields: vec![field("id", 0, 2, "u16"), field("hp", 2, 2, "u16")],
                },
            ),
            (
                "B".to_string(),
                Codec {
                    name: "msg".into(),
                    fields: vec![field("hp", 0, 4, "u32"), field("id", 4, 2, "u16")],
                },
            ),
        ])
    }

    fn trace() -> Store {
        let mut store = Store::memory("i").unwrap();
        store
            .ingest(
                "s",
                0,
                &records(vec![
                    ev(
                        "core.marker",
                        0,
                        1,
                        serde_json::json!({"layout": "A"}),
                        |_| {},
                    ),
                    // id 7, hp 100 in layout A
                    ev(
                        "app.msg",
                        1,
                        1,
                        serde_json::json!({"bytes": "07006400"}),
                        |_| {},
                    ),
                    ev(
                        "core.marker",
                        2,
                        1,
                        serde_json::json!({"layout": "B"}),
                        |_| {},
                    ),
                    // hp 100000, id 9 in layout B
                    ev(
                        "app.msg",
                        3,
                        1,
                        serde_json::json!({"bytes": "a0860100" .to_string() + "0900"}),
                        |_| {},
                    ),
                    ev(
                        "app.msg",
                        4,
                        1,
                        serde_json::json!({"bytes": "0102"}),
                        |_| {},
                    ),
                ]),
            )
            .unwrap();
        store
    }

    #[test]
    fn two_layouts_decode_under_their_own_context_with_provenance() {
        let mut store = trace();
        let contexts = contexts_from_markers(&store, &codecs()).unwrap();
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0].to_seq, Some(2));
        let stats = reprocess(&mut store, &contexts, &["app.msg".into()], "initial").unwrap();
        assert_eq!((stats.decoded, stats.short_payload), (2, 1));
        let a = decoded(&store, 2, None).unwrap();
        assert_eq!(
            a.iter().find(|d| d.field == "hp").unwrap().value,
            json!(100)
        );
        assert_eq!(
            a.iter().find(|d| d.field == "hp").unwrap().byte_off,
            Some(2)
        );
        let b = decoded(&store, 4, None).unwrap();
        assert_eq!(
            b.iter().find(|d| d.field == "hp").unwrap().value,
            json!(100000)
        );
        assert_eq!(
            b.iter().find(|d| d.field == "id").unwrap().byte_off,
            Some(4)
        );
        // The short payload is recorded, not guessed.
        assert!(
            decoded(&store, 5, None)
                .unwrap()
                .iter()
                .any(|d| d.field == "_error")
        );
    }

    #[test]
    fn same_schema_different_codec_hash() {
        let a = codecs()["A"].clone();
        let mut swapped = a.clone();
        swapped.fields[0].offset = 2;
        swapped.fields[1].offset = 0;
        assert_eq!(a.schema_hash(), swapped.schema_hash());
        assert_ne!(a.codec_hash(), swapped.codec_hash());
        // A different type is a different schema.
        assert_ne!(a.schema_hash(), codecs()["B"].schema_hash());
    }

    #[test]
    fn reprocessing_with_a_corrected_layout_is_a_new_revision() {
        let mut store = trace();
        let mut codecs = codecs();
        let first = contexts_from_markers(&store, &codecs).unwrap();
        let r1 = reprocess(&mut store, &first, &["app.msg".into()], "initial").unwrap();
        // The first guess was wrong: hp is big endian in layout A.
        codecs.get_mut("A").unwrap().fields[1].endian = Some("be".into());
        let second = contexts_from_markers(&store, &codecs).unwrap();
        let r2 = reprocess(
            &mut store,
            &second,
            &["app.msg".into()],
            "A.hp is big endian",
        )
        .unwrap();
        assert_eq!(r2.revision, r1.revision + 1);
        let old = decoded(&store, 2, Some(r1.revision)).unwrap();
        let new = decoded(&store, 2, Some(r2.revision)).unwrap();
        assert_eq!(
            old.iter().find(|d| d.field == "hp").unwrap().value,
            json!(100)
        );
        assert_eq!(
            new.iter().find(|d| d.field == "hp").unwrap().value,
            json!(25600)
        );
        // Default is the latest; the observation itself never changed.
        assert_eq!(decoded(&store, 2, None).unwrap(), new);
        let revs = revisions(&store).unwrap();
        assert_eq!(revs.len(), 2);
        assert_eq!(revs[1].1, Some(revs[0].0));
        assert_ne!(revs[0].2, revs[1].2);
        let payload: String = store
            .conn()
            .query_row("SELECT payload FROM events WHERE seq=2", [], |r| r.get(0))
            .unwrap();
        assert!(payload.contains("07006400"));
    }

    #[test]
    fn an_unknown_layout_leaves_events_counted_undecoded() {
        let mut store = trace();
        let mut only_a = codecs();
        only_a.remove("B");
        let ctx = contexts_from_markers(&store, &only_a).unwrap();
        let stats = reprocess(&mut store, &ctx, &["app.msg".into()], "A only").unwrap();
        assert_eq!(stats.decoded, 1);
        assert_eq!(stats.no_context, 2);
    }
}
