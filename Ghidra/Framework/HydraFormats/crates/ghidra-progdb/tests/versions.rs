//! Version policy: databases Java would have to upgrade (or that are newer than this port) are
//! refused with a clear error, never half-read.

use std::path::{Path, PathBuf};

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::{AddressSpaces, ProgError, ProgramDb, SpaceDef};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures/legacy-12.1.4")
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

fn spaces() -> AddressSpaces {
    let ram = SpaceDef {
        name: "ram".into(),
        id: 433,
        bits: 64,
    };
    let reg = SpaceDef {
        name: "register".into(),
        id: 548,
        bits: 32,
    };
    let stack = SpaceDef {
        name: "stack".into(),
        id: 53,
        bits: 64,
    };
    AddressSpaces::new(vec![ram, reg, stack], "ram")
}

/// Copy of the fixture whose stored "DB Version" value ("32") is replaced by `version` (two
/// digits, so the record keeps its length).
fn with_version(version: &str, name: &str) -> PathBuf {
    assert_eq!(version.len(), 2);
    let mut data = std::fs::read(fixture()).unwrap();
    let key = data
        .windows(10)
        .position(|w| w == b"DB Version")
        .expect("DB Version key");
    let lo = key.saturating_sub(4096);
    let hi = (key + 4096).min(data.len());
    let pat = [0u8, 0, 0, 2, b'3', b'2'];
    let at = lo
        + data[lo..hi]
            .windows(pat.len())
            .position(|w| w == pat)
            .expect("stored value");
    data[at + 4..at + 6].copy_from_slice(version.as_bytes());
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn open(path: &Path) -> Result<ProgramDb<BufferFile>, ProgError> {
    ProgramDb::open(BufferFile::open(path, true).unwrap(), spaces())
}

#[test]
fn current_and_older_readable_versions_open() {
    assert_eq!(open(&fixture()).unwrap().stored_version(), 32);
    for (v, n) in [("33", "v33.gbf"), ("19", "v19.gbf")] {
        let db = open(&with_version(v, n)).unwrap();
        assert_eq!(db.stored_version(), v.parse::<i32>().unwrap());
    }
}

#[test]
fn newer_version_is_refused() {
    match open(&with_version("34", "v34.gbf")) {
        Err(ProgError::NewerVersion {
            stored: 34,
            supported: 33,
        }) => {}
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn versions_before_19_need_a_java_upgrade() {
    for (v, n) in [("18", "v18.gbf"), ("10", "v10.gbf")] {
        match open(&with_version(v, n)) {
            Err(e @ ProgError::UpgradeRequired { minimum: 19, .. }) => {
                assert!(e.to_string().contains("upgraded by Ghidra"));
            }
            other => panic!("{:?}", other.err()),
        }
    }
}
