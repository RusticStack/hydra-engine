//! Tests for the packed file reader. The `.pdb` fixtures in `testdata/pack` were written by
//! `ItemSerializer` through `oracle/PackOracle.java` and read back by `ItemDeserializer`.

use super::*;
use std::path::PathBuf;

fn pdb(name: &str) -> Vec<u8> {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "../../testdata/pack", name]
        .iter()
        .collect();
    std::fs::read(p).unwrap()
}

#[test]
fn crc32_check_value() {
    assert_eq!(inflate::crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(inflate::crc32(b""), 0);
}

#[test]
fn inflate_stored_fixed_and_errors() {
    let stored = [1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'];
    let (o, used) = inflate::inflate(&stored, 10).unwrap();
    assert_eq!((o.as_slice(), used), (&b"abc"[..], 8));
    // fixed Huffman "a" (zlib's output for a single byte)
    let (o, used) = inflate::inflate(&[0x4b, 0x04, 0x00], 10).unwrap();
    assert_eq!((o.as_slice(), used), (&b"a"[..], 3));
    // limit enforced
    assert!(matches!(
        inflate::inflate(&stored, 2),
        Err(PackError::TooLarge)
    ));
    // bad stored length check, reserved block type, truncation
    assert!(inflate::inflate(&[1, 3, 0, 0, 0, 1, 2, 3], 10).is_err());
    assert!(matches!(
        inflate::inflate(&[0x07], 10),
        Err(PackError::Inflate(_))
    ));
    assert!(matches!(
        inflate::inflate(&[], 10),
        Err(PackError::Truncated)
    ));
}

#[test]
fn text_fixture() {
    let b = pdb("text.pdb");
    assert!(is_packed(&b));
    let (h, data) = unpack(&b).unwrap();
    assert_eq!(h.item_name, "text");
    assert_eq!(h.content_type.as_deref(), Some("Program"));
    assert_eq!((h.file_type, h.length), (0, 15425));
    let expect: Vec<u8> = (0..400)
        .flat_map(|i| format!("line {i}: the quick brown fox {} jumps\n", i * i % 97).into_bytes())
        .collect();
    assert_eq!(data, expect);
}

#[test]
fn blank_content_type_is_none() {
    let (h, data) = unpack(&pdb("short.pdb")).unwrap();
    assert_eq!(h.content_type, None);
    assert_eq!(data, b"hello hello hello hello, packed world\n");
}

#[test]
fn incompressible_fixture_uses_a_stored_block() {
    let b = pdb("rnd.pdb");
    let (h, data) = unpack(&b).unwrap();
    assert_eq!(h.length, 3000);
    assert_eq!(data.len(), 3000);
    // a stored block carries the payload verbatim somewhere in the file
    assert!(b.windows(64).any(|w| w == &data[100..164]));
}

#[test]
fn corruption_is_detected_not_a_panic() {
    let good = pdb("text.pdb");
    // every truncation fails cleanly
    for n in 0..good.len() {
        assert!(unpack(&good[..n]).is_err(), "prefix {n}");
    }
    // a flipped byte in the compressed body fails (crc, inflate or size)
    let (_, zip) = read_header(&good).unwrap();
    let mut bad = good.clone();
    bad[zip + 60] ^= 0x55;
    assert!(unpack(&bad).is_err());
    // magic, version, stream header
    let mut m = good.clone();
    m[7] ^= 1;
    assert!(!is_packed(&m));
    assert!(matches!(unpack(&m), Err(PackError::Invalid(_))));
    let mut v = good.clone();
    v[17] = 2; // version int, last byte
    assert!(matches!(unpack(&v), Err(PackError::Invalid(_))));
    let mut s = good.clone();
    s[0] = 0;
    assert!(unpack(&s).is_err());
    assert!(!is_packed(&good[..10]));
}

fn modified_utf(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        match u {
            1..=0x7f => out.push(u as u8),
            0 | 0x80..=0x7ff => {
                out.push(0xc0 | (u >> 6) as u8);
                out.push(0x80 | (u & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (u >> 12) as u8);
                out.push(0x80 | ((u >> 6) & 0x3f) as u8);
                out.push(0x80 | (u & 0x3f) as u8);
            }
        }
    }
    let mut r = (out.len() as u16).to_be_bytes().to_vec();
    r.extend(out);
    r
}

/// Hand-built packed file: header as 1024 byte block-data records, then a ZIP entry with a
/// stored deflate block and the sizes in the local header (no data descriptor).
fn build(name: &str, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(0x2e30_2126_34e9_2c20_i64.to_be_bytes());
    data.extend(1i32.to_be_bytes());
    data.extend(modified_utf(name));
    data.extend(modified_utf(content_type));
    data.extend(0i32.to_be_bytes());
    data.extend((payload.len() as i64).to_be_bytes());
    let mut out = vec![0xac, 0xed, 0, 5];
    for chunk in data.chunks(1024) {
        if chunk.len() < 256 {
            out.extend([0x77, chunk.len() as u8]);
        } else {
            out.push(0x7a);
            out.extend((chunk.len() as i32).to_be_bytes());
        }
        out.extend(chunk);
    }
    let mut deflate = vec![1];
    deflate.extend((payload.len() as u16).to_le_bytes());
    deflate.extend((!(payload.len() as u16)).to_le_bytes());
    deflate.extend(payload);
    out.extend(0x0403_4b50u32.to_le_bytes());
    out.extend([20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
    out.extend(inflate::crc32(payload).to_le_bytes());
    out.extend((deflate.len() as u32).to_le_bytes());
    out.extend((payload.len() as u32).to_le_bytes());
    out.extend(11u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(b"FOLDER_ITEM");
    out.extend(deflate);
    out
}

#[test]
fn synthetic_packed_file_with_long_unicode_name_spanning_blocks() {
    let name = "n\u{e9}\u{4e2d}\u{1f600}".repeat(300); // more than 1024 header bytes
    let payload = b"payload bytes";
    let (h, data) = unpack(&build(&name, "Prog", payload)).unwrap();
    assert_eq!(h.item_name, name);
    assert_eq!(h.content_type.as_deref(), Some("Prog"));
    assert_eq!(data, payload);
}

#[test]
fn synthetic_rejections() {
    let ok = build("x", "T", b"data");
    assert!(unpack(&ok).is_ok());
    // blank name
    assert!(matches!(
        unpack(&build("  ", "T", b"data")),
        Err(PackError::Invalid(_))
    ));
    // wrong entry name
    let mut w = ok.clone();
    let at = w.windows(11).position(|x| x == b"FOLDER_ITEM").unwrap();
    w[at] = b'G';
    assert!(unpack(&w).is_err());
    // crc mismatch
    let mut c = ok.clone();
    let sig = 0x0403_4b50u32.to_le_bytes();
    let at = c.windows(4).position(|x| x == sig).unwrap();
    c[at + 14] ^= 1;
    assert!(matches!(unpack(&c), Err(PackError::Checksum)));
    // suspicious compression ratio: header length far beyond the file size
    let mut r = ok.clone();
    let big = 1_000_000i64.to_be_bytes();
    let at = 4 + 2 + 8 + 4 + 2 + 1 + 2 + 1 + 4;
    r[at..at + 8].copy_from_slice(&big);
    assert!(matches!(unpack(&r), Err(PackError::Invalid(_))));
}
