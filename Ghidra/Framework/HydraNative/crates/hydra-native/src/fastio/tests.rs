use super::*;
use std::fs;

fn tmp(name: &str) -> PathBuf {
    let root = std::env::var_os("HYDRA_FASTIO_TMP").map_or_else(std::env::temp_dir, PathBuf::from);
    let d = root.join(format!("hydra-fastio-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("temp dir");
    d
}

fn copy_blob(ops: &[(u8, u8, u64, &Path, &Path)]) -> Vec<u8> {
    let mut b = (ops.len() as u32).to_le_bytes().to_vec();
    for (mode, flags, size, src, dst) in ops {
        let (s, d) = (src.to_str().unwrap(), dst.to_str().unwrap());
        b.push(*mode);
        b.push(*flags);
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&(s.len() as u32).to_le_bytes());
        b.extend_from_slice(&(d.len() as u32).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.extend_from_slice(d.as_bytes());
    }
    b
}

fn flush_blob(ops: &[(u8, &Path)]) -> Vec<u8> {
    let mut b = (ops.len() as u32).to_le_bytes().to_vec();
    for (kind, p) in ops {
        let s = p.to_str().unwrap();
        b.push(*kind);
        b.extend_from_slice(&(s.len() as u32).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b
}

fn finish(job: *mut IoJob) -> (i32, Failure) {
    // SAFETY: `job` was just made by a start function and is freed below, once.
    unsafe {
        let st = hydra_io_wait(job, 30_000);
        let mut kind = 0i32;
        let mut buf = [0u8; 512];
        let n = hydra_io_error(job, &mut kind, buf.as_mut_ptr(), buf.len() as u64) as usize;
        let msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned();
        hydra_io_free(job);
        (st, Failure { kind, message: msg })
    }
}

fn outcomes(job: *const IoJob, n: usize) -> Vec<u8> {
    let mut o = vec![0u8; n];
    // SAFETY: `job` is live and `o` has `n` bytes.
    unsafe { hydra_io_outcomes(job, o.as_mut_ptr(), n as u64) };
    o
}

fn writable(p: &Path) {
    let mut perms = fs::metadata(p).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)] // test cleanup of a temp file
    perms.set_readonly(false);
    let _ = fs::set_permissions(p, perms);
}

#[test]
fn copies_links_and_makes_folders() {
    let d = tmp("copy");
    let (a, b) = (d.join("a.bin"), d.join("b.bin"));
    fs::write(&a, vec![7u8; 5000]).unwrap();
    fs::write(&b, b"small").unwrap();
    let sub = d.join("out/sub");
    let blob = copy_blob(&[
        (MODE_MKDIR, 0, 0, &sub, &sub),
        (MODE_LINK, 0, 5000, &a, &sub.join("a.bin")),
        (MODE_COPY, FLAG_FLUSH, 5, &b, &sub.join("b.bin")),
    ]);
    let job = start_copy(parse_copy(&blob).unwrap(), 4);
    // SAFETY: just made.
    let st = unsafe { hydra_io_wait(job, 30_000) };
    assert_eq!(st, JOB_OK);
    assert_eq!(
        outcomes(job, 3),
        vec![OUT_DIR, OUT_LINKED, OUT_COPIED_FLUSHED]
    );
    // SAFETY: just made.
    assert_eq!(unsafe { hydra_io_progress(job) }, 5005);
    // SAFETY: freed once.
    unsafe { hydra_io_free(job) };
    assert_eq!(fs::read(sub.join("a.bin")).unwrap().len(), 5000);
    assert_eq!(fs::read(sub.join("b.bin")).unwrap(), b"small");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn copy_keeps_the_modification_time() {
    let d = tmp("times");
    let (a, to) = (d.join("a.bin"), d.join("copy.bin"));
    fs::write(&a, b"x").unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    File::options()
        .write(true)
        .open(&a)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let blob = copy_blob(&[(MODE_COPY, 0, 1, &a, &to)]);
    let (st, _) = finish(start_copy(parse_copy(&blob).unwrap(), 1));
    assert_eq!(st, JOB_OK);
    let got = fs::metadata(&to).unwrap().modified().unwrap();
    assert_eq!(got, old);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn copy_refuses_an_existing_destination() {
    let d = tmp("exists");
    let (a, to) = (d.join("a.bin"), d.join("to.bin"));
    fs::write(&a, b"new").unwrap();
    fs::write(&to, b"old").unwrap();
    let blob = copy_blob(&[(MODE_COPY, 0, 3, &a, &to)]);
    let (st, f) = finish(start_copy(parse_copy(&blob).unwrap(), 1));
    assert_eq!(st, JOB_FAILED);
    assert_eq!(f.kind, KIND_EXISTS, "{f:?}");
    assert_eq!(fs::read(&to).unwrap(), b"old");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_gone_source_is_skipped_only_when_asked() {
    let d = tmp("gone");
    let gone = d.join("gone.bin");
    let blob = copy_blob(&[(MODE_COPY, FLAG_SKIP_GONE, 1, &gone, &d.join("x"))]);
    let job = start_copy(parse_copy(&blob).unwrap(), 2);
    // SAFETY: just made.
    assert_eq!(unsafe { hydra_io_wait(job, 30_000) }, JOB_OK);
    assert_eq!(outcomes(job, 1), vec![OUT_SKIPPED]);
    // SAFETY: freed once.
    unsafe { hydra_io_free(job) };
    let blob = copy_blob(&[(MODE_COPY, 0, 1, &gone, &d.join("y"))]);
    let (st, f) = finish(start_copy(parse_copy(&blob).unwrap(), 2));
    assert_eq!((st, f.kind), (JOB_FAILED, KIND_NOT_FOUND));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn flush_forces_every_file_and_keeps_read_only_files_read_only() {
    let d = tmp("flush");
    let mut files = Vec::new();
    for i in 0..20 {
        let p = d.join(format!("f{i}.bin"));
        fs::write(&p, vec![i as u8; 1000]).unwrap();
        files.push(p);
    }
    let mut perms = fs::metadata(&files[3]).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&files[3], perms).unwrap();
    let mut ops: Vec<(u8, &Path)> = files.iter().map(|p| (FLUSH_OWNED, p.as_path())).collect();
    ops.push((FLUSH_DIR, d.as_path()));
    let (st, f) = finish(start_flush(parse_flush(&flush_blob(&ops)).unwrap(), 4));
    assert_eq!(st, JOB_OK, "{f:?}");
    assert!(fs::metadata(&files[3]).unwrap().permissions().readonly());
    // a linked read-only file is left alone
    let blob = flush_blob(&[(FLUSH_LINKED, &files[3])]);
    let (st, f) = finish(start_flush(parse_flush(&blob).unwrap(), 1));
    assert_eq!(st, JOB_OK, "{f:?}");
    assert!(fs::metadata(&files[3]).unwrap().permissions().readonly());
    files.iter().for_each(|p| writable(p));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn flush_of_a_missing_file_fails_after_every_op_ended() {
    let d = tmp("flushfail");
    let ok = d.join("ok.bin");
    fs::write(&ok, b"x").unwrap();
    let gone = d.join("gone.bin");
    let blob = flush_blob(&[(FLUSH_OWNED, &ok), (FLUSH_OWNED, &gone), (FLUSH_OWNED, &ok)]);
    let (st, f) = finish(start_flush(parse_flush(&blob).unwrap(), 3));
    assert_eq!((st, f.kind), (JOB_FAILED, KIND_NOT_FOUND));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_malformed_blob_is_refused() {
    assert!(parse_flush(&[1, 0, 0, 0, 9]).is_none());
    assert!(parse_copy(&[1, 0, 0, 0]).is_none());
    assert!(parse_flush(&flush_blob(&[(FLUSH_OWNED, Path::new("a"))])[..9]).is_none());
    let mut extra = flush_blob(&[(FLUSH_OWNED, Path::new("a"))]);
    extra.push(0);
    assert!(parse_flush(&extra).is_none());
    // SAFETY: a null blob with length 0 is allowed and is not a valid job description.
    unsafe {
        assert!(hydra_io_flush_start(std::ptr::null(), 0, 1).is_null());
    }
}

#[test]
fn cancel_after_the_end_changes_nothing() {
    let d = tmp("cancel");
    let a = d.join("a");
    fs::write(&a, b"x").unwrap();
    let job = start_flush(parse_flush(&flush_blob(&[(FLUSH_OWNED, &a)])).unwrap(), 1);
    // SAFETY: just made, freed once.
    unsafe {
        assert_eq!(hydra_io_wait(job, 30_000), JOB_OK);
        hydra_io_cancel(job);
        assert_eq!(hydra_io_wait(job, 0), JOB_OK);
        hydra_io_free(job);
    }
    let _ = fs::remove_dir_all(&d);
}

/// Timing probe, not a check: `cargo test --release -- --ignored --nocapture probe_copy`.
#[test]
#[ignore]
fn probe_copy() {
    let d = tmp("probe");
    let src = d.join("src");
    fs::create_dir_all(&src).unwrap();
    let mut names = Vec::new();
    for i in 0..10 {
        let p = src.join(format!("f{i}.prp"));
        fs::write(&p, vec![i as u8; 300]).unwrap();
        names.push(p);
    }
    for threads in [1usize, 2, 4, 8] {
        let mut times = Vec::new();
        for round in 0..30 {
            let dst = d.join(format!("t{threads}-{round}"));
            fs::create_dir_all(&dst).unwrap();
            let tos: Vec<PathBuf> = names
                .iter()
                .map(|p| dst.join(p.file_name().unwrap()))
                .collect();
            let ops: Vec<(u8, u8, u64, &Path, &Path)> = names
                .iter()
                .zip(&tos)
                .map(|(a, b)| (MODE_COPY, 0u8, 300u64, a.as_path(), b.as_path()))
                .collect();
            let blob = copy_blob(&ops);
            let t = std::time::Instant::now();
            let (st, _) = finish(start_copy(parse_copy(&blob).unwrap(), threads));
            times.push(t.elapsed().as_micros());
            assert_eq!(st, JOB_OK);
        }
        times.sort_unstable();
        println!(
            "copy threads {threads}: median {} us, max {} us",
            times[15], times[29]
        );
        let mut times = Vec::new();
        for round in 0..30 {
            let dst = d.join(format!("t{threads}-{round}"));
            let tos: Vec<PathBuf> = names
                .iter()
                .map(|p| dst.join(p.file_name().unwrap()))
                .collect();
            let ops: Vec<(u8, &Path)> = tos.iter().map(|p| (FLUSH_OWNED, p.as_path())).collect();
            let blob = flush_blob(&ops);
            let t = std::time::Instant::now();
            let (st, _) = finish(start_flush(parse_flush(&blob).unwrap(), threads));
            times.push(t.elapsed().as_micros());
            assert_eq!(st, JOB_OK);
        }
        times.sort_unstable();
        println!(
            "flush threads {threads}: median {} us, max {} us",
            times[15], times[29]
        );
    }
    let mut times = Vec::new();
    for round in 0..30 {
        let dst = d.join(format!("j-{round}"));
        fs::create_dir_all(&dst).unwrap();
        let t = std::time::Instant::now();
        for p in &names {
            fs::copy(p, dst.join(p.file_name().unwrap())).unwrap();
        }
        times.push(t.elapsed().as_micros());
    }
    times.sort_unstable();
    println!("serial std::fs::copy: median {} us", times[15]);
    let _ = fs::remove_dir_all(&d);
}
