//! The packed legacy fixture unpacks to exactly the checked-in `.gbf` and opens as a database.

use std::path::{Path, PathBuf};

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferFile;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn legacy_pdb_unpacks_to_the_original_gbf_and_opens() {
    let (h, data) =
        ghidra_fmt_pack::unpack_file(manifest().join("../../testdata/pack/legacy.pdb")).unwrap();
    assert_eq!(h.item_name, "legacy");
    assert_eq!(h.content_type.as_deref(), Some("Program"));
    assert_eq!(h.length, 1_572_864);
    let original = std::fs::read(
        manifest()
            .join("../../../../Features/HeadlessSession/examples/fixtures/legacy-12.1.4")
            .join("legacy.rep/idata/00/~00000000.db/db.1.gbf"),
    )
    .unwrap();
    assert!(
        data == original,
        "unpacked bytes differ from the source gbf"
    );

    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let out = dir.join("legacy-unpacked.gbf");
    std::fs::write(&out, &data).unwrap();
    let db = Database::open(BufferFile::open(&out, true).unwrap()).unwrap();
    assert_eq!(db.table("Comment History").unwrap().record_count(), 228);
    std::fs::remove_file(out).unwrap();
}
