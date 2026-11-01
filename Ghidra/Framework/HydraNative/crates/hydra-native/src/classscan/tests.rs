//! Behaviour tests for the extension-point class scan.
//!
//! These are the definition of "same behaviour" as the Java scan they replace: one test per
//! observable rule in the module documentation, plus the zip reader's edges (empty jar, ZIP64,
//! truncation, non-UTF-8 names) and the C ABI round trip.

use super::*;

// ---------------------------------------------------------------- a minimal zip writer

/// A stored (uncompressed) zip of `entries`, enough for the central-directory reader under test.
fn zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let at = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local header
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (not read)
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central header
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // time
        central.extend_from_slice(&0u16.to_le_bytes()); // date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&at.to_le_bytes()); // local header offset
        central.extend_from_slice(name);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // end of central directory
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment
    out
}

/// A zip whose end-of-central-directory record is the ZIP64 pair (entries and offsets 64-bit).
fn zip64(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = zip(entries);
    // The plain EOCD is the last 22 bytes: read its central-directory offset and size, then
    // replace it with the ZIP64 record, its locator and an EOCD carrying the max markers.
    let n = out.len();
    let eocd = &out[n - 22..];
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]);
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]);
    out.truncate(n - 22);
    let z64_at = out.len() as u64;
    out.extend_from_slice(&0x0606_4b50u32.to_le_bytes()); // ZIP64 end of central directory
    out.extend_from_slice(&44u64.to_le_bytes()); // size of the record
    out.extend_from_slice(&45u16.to_le_bytes()); // version made by
    out.extend_from_slice(&45u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u32.to_le_bytes()); // disk
    out.extend_from_slice(&0u32.to_le_bytes()); // cd disk
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    out.extend_from_slice(&u64::from(cd_size).to_le_bytes());
    out.extend_from_slice(&u64::from(cd_offset).to_le_bytes());
    out.extend_from_slice(&0x0706_4b50u32.to_le_bytes()); // ZIP64 locator
    out.extend_from_slice(&0u32.to_le_bytes()); // disk
    out.extend_from_slice(&z64_at.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // total disks
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // plain EOCD with the max markers
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn temp_jar(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hydra-classscan-{}-{}", std::process::id(), name));
    std::fs::write(&dir, bytes).expect("write the fixture jar");
    dir
}

// ---------------------------------------------------------------- the Java rules

#[test]
fn extension_point_matches_a_literal_suffix() {
    let got = extension_point("a/b/FooPlugin.class", &["Plugin"]);
    assert_eq!(
        got,
        Some(("a.b.FooPlugin".to_owned(), "Plugin".to_owned()))
    );
}

#[test]
fn extension_point_uses_the_shortest_suffix() {
    // The Java regex backtracks `.*` from the longest, so the shortest remainder wins; the
    // ClassSearcher comment states the same intent.
    assert_eq!(
        extension_point("a/BillBobPlugin.class", &["BobPlugin", "Plugin"]),
        Some(("a.BillBobPlugin".to_owned(), "Plugin".to_owned()))
    );
    assert_eq!(
        extension_point("a/BillBobPlugin.class", &["Plugin", "BobPlugin"]),
        Some(("a.BillBobPlugin".to_owned(), "Plugin".to_owned()))
    );
}

#[test]
fn extension_point_skips_inner_classes() {
    assert_eq!(
        extension_point("a/Outer$InnerPlugin.class", &["Plugin"]),
        None
    );
}

#[test]
fn extension_point_skips_test_classes() {
    assert_eq!(extension_point("a/SomethingTest.class", &["Test"]), None);
    assert_eq!(extension_point("a/FooPluginTest.class", &["Plugin"]), None);
}

#[test]
fn extension_point_cuts_at_the_first_class_extension() {
    // ClassJar uses String.indexOf(".class"), not lastIndexOf: `a/B.class.class` is class `a.B`.
    assert_eq!(
        extension_point("a/B.class.class", &["B"]),
        Some(("a.B".to_owned(), "B".to_owned()))
    );
    // ... and the rest of the name is not part of the class, so a suffix it carries cannot match.
    assert_eq!(extension_point("a/B.class.class", &["class"]), None);
}

#[test]
fn extension_point_requires_the_class_extension() {
    assert_eq!(extension_point("a/FooPlugin.txt", &["Plugin"]), None);
    assert_eq!(extension_point("a/FooPlugin.classx", &["Plugin"]), None);
}

#[test]
fn extension_point_default_and_odd_packages() {
    assert_eq!(
        extension_point("FooPlugin.class", &["Plugin"]),
        Some(("FooPlugin".to_owned(), "Plugin".to_owned()))
    );
    // A leading dot leaves lastIndexOf('.') == 0, which the Java keeps as the whole name.
    assert_eq!(
        extension_point(".FooPlugin.class", &["Plugin"]),
        Some((".FooPlugin".to_owned(), "Plugin".to_owned()))
    );
}

#[test]
fn extension_point_no_suffix_no_hit() {
    assert_eq!(extension_point("a/Foo.class", &["Plugin"]), None);
}

#[test]
fn shortest_suffix_prefers_the_shorter_one() {
    assert_eq!(shortest_suffix("ABPlugin", &["Plugin", "BPlugin"]), Some("Plugin"));
    assert_eq!(shortest_suffix("ABPlugin", &["BPlugin"]), Some("BPlugin"));
    assert_eq!(shortest_suffix("ABPlugin", &[]), None);
    assert_eq!(shortest_suffix("ABPlugin", &["Other"]), None);
}

// ---------------------------------------------------------------- the scan

#[test]
fn scan_jars_reads_the_central_directory_in_order() {
    let jar = temp_jar(
        "order.jar",
        &zip(&[
            (b"a/OnePlugin.class", b"x"),
            (b"a/readme.txt", b"x"),
            (b"a/TwoPlugin.class", b"x"),
            (b"a/Two$Inner.class", b"x"),
        ]),
    );
    let hits = scan_jars(&[jar.as_path()], &["Plugin"]).expect("scan");
    assert_eq!(
        hits,
        vec![
            Hit { jar: 0, name: "a.OnePlugin".to_owned(), suffix: "Plugin".to_owned() },
            Hit { jar: 0, name: "a.TwoPlugin".to_owned(), suffix: "Plugin".to_owned() },
        ]
    );
    std::fs::remove_file(jar).ok();
}

#[test]
fn scan_jars_numbers_the_jars_it_was_given() {
    let one = temp_jar("first.jar", &zip(&[(b"x/APlugin.class", b"")]));
    let two = temp_jar("second.jar", &zip(&[(b"x/BPlugin.class", b"")]));
    let hits = scan_jars(&[one.as_path(), two.as_path()], &["Plugin"]).expect("scan");
    assert_eq!(hits.iter().map(|h| h.jar).collect::<Vec<_>>(), vec![0, 1]);
    std::fs::remove_file(one).ok();
    std::fs::remove_file(two).ok();
}

#[test]
fn scan_jars_accepts_an_empty_jar() {
    let jar = temp_jar("empty.jar", &zip(&[]));
    assert_eq!(scan_jars(&[jar.as_path()], &["Plugin"]), Ok(Vec::new()));
    std::fs::remove_file(jar).ok();
}

#[test]
fn scan_jars_reads_zip64() {
    let jar = temp_jar("z64.jar", &zip64(&[(b"a/ZPlugin.class", b"x")]));
    let hits = scan_jars(&[jar.as_path()], &["Plugin"]).expect("scan");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "a.ZPlugin");
    std::fs::remove_file(jar).ok();
}

#[test]
fn scan_jars_fails_on_a_file_that_is_not_a_zip() {
    let jar = temp_jar("notzip.jar", b"this is not a zip file at all");
    assert_eq!(scan_jars(&[jar.as_path()], &["Plugin"]), Err(ScanError::BadZip));
    std::fs::remove_file(jar).ok();
}

#[test]
fn scan_jars_fails_on_a_truncated_central_directory() {
    let mut bytes = zip(&[(b"a/APlugin.class", b"")]);
    // Point the end-of-central-directory record past the end of the file.
    let n = bytes.len();
    bytes[n - 6..n - 2].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    let jar = temp_jar("truncated.jar", &bytes);
    assert_eq!(scan_jars(&[jar.as_path()], &["Plugin"]), Err(ScanError::BadZip));
    std::fs::remove_file(jar).ok();
}

#[test]
fn scan_jars_fails_on_a_missing_file() {
    let missing = std::env::temp_dir().join("hydra-classscan-does-not-exist.jar");
    std::fs::remove_file(&missing).ok();
    assert_eq!(scan_jars(&[missing.as_path()], &["Plugin"]), Err(ScanError::BadZip));
}

#[test]
fn scan_jars_fails_on_a_non_utf8_entry_name() {
    let jar = temp_jar("latin1.jar", &zip(&[(b"a/F\xffPlugin.class", b"")]));
    assert_eq!(scan_jars(&[jar.as_path()], &["Plugin"]), Err(ScanError::NotUtf8));
    std::fs::remove_file(jar).ok();
}

// ---------------------------------------------------------------- the C ABI

#[test]
fn abi_round_trip_encodes_the_hits() {
    let jar = temp_jar("abi.jar", &zip(&[(b"p/QPlugin.class", b"")]));
    let mut paths = jar.to_string_lossy().as_bytes().to_vec();
    paths.push(0);
    let mut suffixes = b"Plugin\0".to_vec();
    suffixes.push(0);
    // SAFETY: both buffers are valid for their lengths.
    let scan = unsafe {
        hydra_cs_scan(paths.as_ptr(), paths.len() as u64, suffixes.as_ptr(), suffixes.len() as u64)
    };
    assert!(!scan.is_null());
    // SAFETY: `scan` comes from hydra_cs_scan above.
    let len = unsafe { hydra_cs_len(scan) };
    let mut out = vec![0u8; usize::try_from(len).expect("length")];
    // SAFETY: `scan` is live and `out` holds `len` bytes.
    let copied = unsafe { hydra_cs_copy(scan, out.as_mut_ptr(), len) };
    assert_eq!(copied, len);
    // SAFETY: the scan is freed exactly once here.
    unsafe { hydra_cs_free(scan) };
    let jar_index = u32::from_le_bytes(out[0..4].try_into().expect("jar index"));
    let name_len = u32::from_le_bytes(out[4..8].try_into().expect("name length")) as usize;
    let suffix_len = u32::from_le_bytes(out[8..12].try_into().expect("suffix length")) as usize;
    assert_eq!(jar_index, 0);
    assert_eq!(&out[12..12 + name_len], b"p.QPlugin");
    assert_eq!(&out[12 + name_len..12 + name_len + suffix_len], b"Plugin");
    std::fs::remove_file(jar).ok();
}

#[test]
fn abi_reports_failures_as_null() {
    let paths = b"/nonexistent/hydra-classscan.jar\0";
    let suffixes = b"Plugin\0";
    // SAFETY: both buffers are valid for their lengths.
    let scan = unsafe {
        hydra_cs_scan(paths.as_ptr(), paths.len() as u64, suffixes.as_ptr(), suffixes.len() as u64)
    };
    assert!(scan.is_null());
    // SAFETY: null is a valid argument to free.
    unsafe { hydra_cs_free(scan) };
    assert_eq!(hydra_cs_abi_version(), CS_ABI_VERSION);
}
