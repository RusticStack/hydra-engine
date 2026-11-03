use super::*;

#[test]
fn hex_image_base_matches_big_integer_long_value() {
    assert_eq!(parse_hex_i64("140000000").unwrap(), 0x1_4000_0000);
    assert_eq!(parse_hex_i64("-1000").unwrap(), -0x1000);
    assert_eq!(parse_hex_i64("ffffffffffffffff").unwrap(), -1);
    assert_eq!(parse_hex_i64("1ffffffffffffffff").unwrap(), -1);
    assert!(parse_hex_i64("zz").is_err());
}

#[test]
fn address_display_matches_the_oracle_format() {
    let a = Address::Space {
        space: "ram".into(),
        offset: 0x1_4000_1000,
    };
    assert_eq!(a.to_string(), "ram:140001000");
    assert_eq!(Address::NoAddress.to_string(), "NO_ADDRESS");
    assert_eq!(Address::ExtFrom.to_string(), "EXT_FROM");
}

#[test]
fn error_messages_name_the_problem() {
    let e = ProgError::UpgradeRequired {
        stored: 18,
        minimum: 19,
    };
    assert!(e.to_string().contains("upgraded by Ghidra"));
    let e = ProgError::NewerVersion {
        stored: 40,
        supported: 33,
    };
    assert!(e.to_string().contains("newer"));
}

#[test]
fn byte_mapping_scheme_decodes_and_rejects_like_java() {
    use crate::memread::ByteMappingScheme;
    assert!(ByteMappingScheme::from_encoded(0).is_ok());
    assert!(ByteMappingScheme::from_encoded((2 << 7) | 4).is_ok());
    // more mapped than source bytes, and a zero count
    assert!(ByteMappingScheme::from_encoded((5 << 7) | 4).is_err());
    assert!(ByteMappingScheme::from_encoded(4).is_err());
}

#[test]
fn byte_mapped_reads_follow_the_scheme_over_real_memory() {
    use crate::memread::ByteMappingScheme;
    use ghidra_fmt_gbf::BufferFile;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = dir.join(
        "../../../../Features/HeadlessSession/examples/fixtures/legacy-12.1.4-analysed/legacy.rep/idata/00/~00000000.db/db.1.gbf",
    );
    let oracle =
        std::fs::read_to_string(dir.join("../../testdata/oracleprog-legacy-12.1.4-analysed.txt"))
            .unwrap();
    let mut defs = Vec::new();
    let mut default = String::new();
    for l in oracle.lines() {
        if let Some(d) = l.strip_prefix("default_space=") {
            default = d.to_owned();
        }
        if let Some(rest) = l.strip_prefix("space ") {
            let get = |k: &str| {
                rest.split(' ')
                    .find_map(|p| p.strip_prefix(k))
                    .unwrap()
                    .to_owned()
            };
            defs.push(SpaceDef {
                name: get("name="),
                id: get("id=").parse().unwrap(),
                bits: get("bits=").parse().unwrap(),
            });
        }
    }
    let db = ProgramDb::open(
        BufferFile::open(fixture, true).unwrap(),
        AddressSpaces::new(defs, &default),
    )
    .unwrap();
    let mem = db.memory().unwrap();
    let base = Address::Space {
        space: "ram".into(),
        offset: 0x1_4000_1000,
    };
    let raw = mem.read(&base, 64).unwrap();

    // 1:1 is a plain read at base + offset
    let one = ByteMappingScheme::from_encoded(0).unwrap();
    assert_eq!(mem.mapped_read(&base, one, 5, 20, 0).unwrap(), raw[5..25]);

    // 2:4 keeps two of every four source bytes
    let scheme = ByteMappingScheme::from_encoded((2 << 7) | 4).unwrap();
    let want: Vec<u8> = raw
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 4 < 2)
        .map(|(_, b)| *b)
        .collect();
    assert_eq!(
        mem.mapped_read(&base, scheme, 0, 10, 0).unwrap(),
        want[..10]
    );
    // starting in the middle of a pattern
    assert_eq!(
        mem.mapped_read(&base, scheme, 3, 8, 0).unwrap(),
        want[3..11]
    );
}

#[test]
fn overlay_spaces_get_the_next_unique_id_and_sort_after_the_others() {
    let space = |name: &str, id: i32| SpaceDef {
        name: name.into(),
        id,
        bits: 64,
    };
    let mut spaces = AddressSpaces::new(vec![space("ram", 433), space("register", 548)], "ram");
    // ram has unique 3 (433 >> 7), register 4; the overlays count on from 5
    spaces.add_overlay("zz", "ram").unwrap();
    spaces.add_overlay("aa", "ram").unwrap();
    assert_eq!(spaces.find("zz").unwrap().id, (5 << 7) | (433 & 0x7f));
    assert_eq!(spaces.find("aa").unwrap().id, (6 << 7) | (433 & 0x7f));
    assert!(spaces.is_overlay("aa"));
    assert_eq!(spaces.overlay_base("aa"), Some("ram"));
    // refused: duplicate name, unknown base, an overlay of an overlay
    assert!(spaces.add_overlay("ram", "ram").is_err());
    assert!(matches!(
        spaces.add_overlay("x", "nope"),
        Err(ProgError::UnknownSpace(_))
    ));
    assert!(spaces.add_overlay("x", "aa").is_err());
}
