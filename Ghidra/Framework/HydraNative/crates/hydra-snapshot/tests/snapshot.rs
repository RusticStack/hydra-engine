use std::ffi::CString;
use std::sync::Arc;

use hydra_snapshot::ffi::*;
use hydra_snapshot::{ReadRequest, Snapshot, encode};

fn sample() -> Vec<u8> {
    let text: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let data = vec![0xAAu8; 16];
    let ovl = vec![1u8, 2, 3, 4];
    encode(
        42,
        &["ram", "ovl"],
        &[
            (0, 0x40_1000, &text),
            (0, 0x40_3000, &data),
            (1, 0x10, &ovl),
        ],
    )
}

#[test]
fn reads_whole_ranges_inside_one_region() {
    let s = Snapshot::from_vec(sample()).unwrap();
    assert_eq!(s.generation(), 42);
    assert_eq!(s.space_index("ram"), Some(0));
    assert_eq!(s.space_index("ovl"), Some(1));
    assert_eq!(s.space_index("register"), None);
    let mut buf = [0u8; 4];
    assert!(s.read(0, 0x40_1000, &mut buf));
    assert_eq!(buf, [0, 1, 2, 3]);
    assert!(s.read(0, 0x40_1000 + 4092, &mut buf));
    assert_eq!(buf, [252, 253, 254, 255]);
    assert!(s.read(1, 0x10, &mut buf));
    assert_eq!(buf, [1, 2, 3, 4]);
}

#[test]
fn refuses_partial_gap_and_foreign_ranges() {
    let s = Snapshot::from_vec(sample()).unwrap();
    let mut buf = [0x55u8; 4];
    assert!(
        !s.read(0, 0x40_1000 + 4094, &mut buf),
        "crosses the end of a region"
    );
    assert!(
        !s.read(0, 0x40_0fff, &mut buf),
        "starts before the first region"
    );
    assert!(
        !s.read(0, 0x40_2000, &mut buf),
        "in the gap between regions"
    );
    assert!(!s.read(1, 0x40_1000, &mut buf), "other space");
    assert!(!s.read(7, 0, &mut buf), "unknown space");
    assert!(!s.read(0, 0x40_1000, &mut []), "empty read");
    assert_eq!(buf, [0x55; 4], "a refused read leaves the buffer alone");
}

#[test]
fn rejects_corrupt_files() {
    let good = sample();
    let mut bad = good.clone();
    bad[0] = b'X';
    assert!(Snapshot::from_vec(bad).is_err(), "magic");
    let mut bad = good.clone();
    bad[8] = 2;
    assert!(Snapshot::from_vec(bad).is_err(), "version");
    assert!(
        Snapshot::from_vec(good[..good.len() - 1].to_vec()).is_err(),
        "truncated data"
    );
    let out_of_order = encode(
        1,
        &["ram"],
        &[(0, 0x2000, &[1u8; 4]), (0, 0x1000, &[2u8; 4])],
    );
    assert!(
        Snapshot::from_vec(out_of_order).is_err(),
        "unsorted regions"
    );
    let overlap = encode(
        1,
        &["ram"],
        &[(0, 0x1000, &[1u8; 8]), (0, 0x1004, &[2u8; 4])],
    );
    assert!(Snapshot::from_vec(overlap).is_err(), "overlapping regions");
    let bad_space = encode(1, &["ram"], &[(3, 0x1000, &[1u8; 8])]);
    assert!(
        Snapshot::from_vec(bad_space).is_err(),
        "space index out of range"
    );
}

#[test]
fn bulk_read_marks_each_request() {
    let s = Snapshot::from_vec(sample()).unwrap();
    let mut reqs = [
        ReadRequest {
            space: 0,
            offset: 0x40_1000,
            length: 2,
            out_offset: 0,
            ..Default::default()
        },
        ReadRequest {
            space: 0,
            offset: 0x40_2000,
            length: 2,
            out_offset: 2,
            ..Default::default()
        },
        ReadRequest {
            space: 1,
            offset: 0x12,
            length: 2,
            out_offset: 4,
            ..Default::default()
        },
        ReadRequest {
            space: 0,
            offset: 0x40_3000,
            length: 4,
            out_offset: 6,
            ..Default::default()
        },
    ];
    let mut out = [0u8; 8];
    assert_eq!(s.read_bulk(&mut reqs, &mut out), 2);
    assert_eq!(
        reqs.map(|r| r.served),
        [1, 0, 1, 0],
        "the last request does not fit the buffer"
    );
    assert_eq!(&out[..6], &[0, 1, 0, 0, 3, 4]);
}

#[test]
fn many_threads_read_one_mapped_file_at_once() {
    let dir = std::env::temp_dir().join(format!("hysnap-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("threads.hysnap");
    std::fs::write(&path, sample()).unwrap();
    let s = Arc::new(Snapshot::open(&path).unwrap());
    let threads = std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .max(2);
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let mut buf = [0u8; 1];
                for i in 0..20_000u64 {
                    let off = (i * 7 + t as u64) % 4096;
                    assert!(s.read(0, 0x40_1000 + off, &mut buf));
                    assert_eq!(buf[0], off as u8);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn c_abi_round_trip() {
    let dir = std::env::temp_dir().join(format!("hysnap-ffi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ffi.hysnap");
    std::fs::write(&path, sample()).unwrap();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: every pointer passed below is live and sized as the C ABI requires.
    unsafe {
        let h = hysnap_open(cpath.as_ptr());
        assert!(!h.is_null());
        assert_eq!(hysnap_generation(h), 42);
        assert_eq!(hysnap_space_index(h, b"ovl".as_ptr(), 3), 1);
        assert_eq!(hysnap_space_index(h, b"nope".as_ptr(), 4), -1);
        let mut buf = [0u8; 3];
        assert_eq!(hysnap_read(h, 0, 0x40_1001, 3, buf.as_mut_ptr()), 1);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(hysnap_read(h, 0, 0x40_2000, 3, buf.as_mut_ptr()), 0);
        let mut reqs = [ReadRequest {
            space: 1,
            offset: 0x10,
            length: 4,
            out_offset: 0,
            ..Default::default()
        }];
        let mut out = [0u8; 4];
        assert_eq!(
            hysnap_read_bulk(h, reqs.as_mut_ptr(), 1, out.as_mut_ptr(), 4),
            1
        );
        assert_eq!(out, [1, 2, 3, 4]);
        hysnap_close(h);
        let missing = CString::new(dir.join("missing.hysnap").to_str().unwrap()).unwrap();
        assert!(hysnap_open(missing.as_ptr()).is_null());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Cross-check with a file written by the engine (ProgramSnapshotFile), when one is given:
/// HYSNAP_SAMPLE=<file.hysnap> cargo test
#[test]
fn engine_written_file_validates() {
    let Ok(path) = std::env::var("HYSNAP_SAMPLE") else {
        return;
    };
    let s = Snapshot::open(&path).unwrap();
    assert!(!s.regions().is_empty());
    for r in s.regions() {
        let mut first = [0u8; 1];
        assert!(s.read(r.space, r.offset, &mut first));
        let mut last = [0u8; 1];
        assert!(s.read(r.space, r.offset + r.length - 1, &mut last));
    }
    eprintln!(
        "{path}: generation {} spaces {:?} regions {}",
        s.generation(),
        s.spaces(),
        s.regions().len()
    );
}
