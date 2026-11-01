use super::*;

fn temp_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hydra-trace-abi-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn call(cmd: &str, ctx: Value, req: Value) -> (i32, Value) {
    let (c, x, r) = (cmd.as_bytes(), ctx.to_string(), req.to_string());
    // SAFETY: the slices live for the call; the reply is freed once below.
    unsafe {
        let reply = hydra_trace_call(
            c.as_ptr(),
            c.len(),
            x.as_ptr(),
            x.len(),
            r.as_ptr(),
            r.len(),
            std::ptr::null(),
        );
        let status = hydra_trace_reply_status(reply);
        let slice =
            std::slice::from_raw_parts(hydra_trace_reply_ptr(reply), hydra_trace_reply_len(reply));
        let value: Value = serde_json::from_slice(slice).unwrap();
        hydra_trace_reply_free(reply);
        (status, value)
    }
}

fn ctx(root: &Path, session: &str, role: &str, gen_: u32) -> Value {
    json!({"root": root.to_string_lossy(), "session": session, "producerGen": gen_,
           "lease": {"role": role, "producerGen": gen_}, "symbolRevision": 7})
}

fn ev(kind: &str, corr: &str) -> Value {
    json!({"kind": kind, "payload": {"corr": corr}})
}

#[test]
fn abi_version() {
    assert_eq!(hydra_trace_abi_version(), TRACE_ABI_VERSION);
}

#[test]
fn open_append_query_and_cursor_stability() {
    let root = temp_root("flow");
    let (st, o) = call(
        "trace_open",
        ctx(&root, "s1", "owner", 1),
        json!({"create": true, "name": "t"}),
    );
    assert_eq!(st, 0, "{o}");
    assert_eq!(o["created"], json!(true));
    let events: Vec<Value> = (0..25)
        .map(|i| ev("core.marker", &format!("c{i}")))
        .collect();
    let (st, a) = call(
        "trace_append",
        ctx(&root, "s1", "owner", 1),
        json!({"events": events}),
    );
    assert_eq!(st, 0, "{a}");
    assert_eq!(a["appended"], json!(25));
    let reader = ctx(&root, "s1", "reader", 0);
    let (_, p1) = call("trace_query", reader.clone(), json!({"limit": 10}));
    assert_eq!(p1["returned"], json!(10));
    let up_to = p1["upTo"].clone();
    let next = p1["next"].clone();
    // more rows arrive; the pinned cursor does not see them
    let more: Vec<Value> = (0..5)
        .map(|i| ev("core.marker", &format!("d{i}")))
        .collect();
    let (st, _) = call(
        "trace_append",
        ctx(&root, "s1", "owner", 1),
        json!({"events": more}),
    );
    assert_eq!(st, 0);
    let (_, p2) = call(
        "trace_query",
        reader.clone(),
        json!({"limit": 100, "after": next, "upTo": up_to}),
    );
    assert_eq!(p2["returned"], json!(15));
    assert_eq!(p2["next"], Value::Null);
    let (_, fresh) = call("trace_query", reader, json!({"limit": 100}));
    assert_eq!(fresh["returned"], json!(30));
}

#[test]
fn reader_cannot_write_and_stale_generation_is_rejected() {
    let root = temp_root("lease");
    call(
        "trace_open",
        ctx(&root, "s2", "owner", 1),
        json!({"create": true}),
    );
    let (st, e) = call(
        "trace_append",
        ctx(&root, "s2", "reader", 0),
        json!({"events": [ev("core.marker", "x")]}),
    );
    assert_eq!(st, 1);
    assert_eq!(e["code"], json!("not_owner"));
    let mut stale = ev("core.marker", "x");
    stale["producer_gen"] = json!(1);
    let (st, a) = call(
        "trace_append",
        ctx(&root, "s2", "owner", 2),
        json!({"events": [stale]}),
    );
    assert_eq!(st, 0);
    assert_eq!(a["appended"], json!(0));
    assert_eq!(a["rejected"], json!(1));
}

#[test]
fn recovery_reindexes_a_tail_and_cuts_a_torn_line() {
    let root = temp_root("recover");
    call(
        "trace_open",
        ctx(&root, "s3", "owner", 1),
        json!({"create": true}),
    );
    let events: Vec<Value> = (0..6)
        .map(|i| ev("core.marker", &format!("c{i}")))
        .collect();
    call(
        "trace_append",
        ctx(&root, "s3", "owner", 1),
        json!({"events": events}),
    );
    // the writer dies: the registry forgets it; a half line is left, and the segment is ahead of
    // the index by two records
    detach("s3");
    let dir = root.join("s3");
    let seg = seg_path(&dir, "api");
    let data = fs::read(&seg).unwrap();
    let scan = raw::scan(&data, "api");
    let mut chain = Chain::new("api");
    let mut extra = Vec::new();
    for r in &scan.records {
        let mut body = r.clone();
        for f in ["n", "prev", "hash"] {
            body.remove(f);
        }
        chain.push(body).unwrap();
    }
    for i in 0..2u64 {
        let rec = json!({"kind": "core.marker", "source_id": "api", "source_seq": 7 + i, "producer_gen": 1,
                         "clock_domain": "external", "t_mono_ns": 0, "confidence": "exact"});
        extra.extend(chain.push(rec.as_object().unwrap().clone()).unwrap());
    }
    extra.extend_from_slice(b"deadbeef {\"half");
    let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
    f.write_all(&extra).unwrap();
    drop(f);
    let (st, o) = call("trace_open", ctx(&root, "s3", "owner", 2), json!({}));
    assert_eq!(st, 0, "{o}");
    assert_eq!(o["recovered"]["reindexed"], json!(2));
    assert!(o["recovered"]["tornTailBytes"].as_u64().unwrap() > 0);
    assert_eq!(o["events"], json!(8));
    // appending chains on after the cut
    let (st, a) = call(
        "trace_append",
        ctx(&root, "s3", "owner", 2),
        json!({"events": [ev("core.marker", "z")]}),
    );
    assert_eq!(st, 0, "{a}");
    let (_, info) = call("trace_info", ctx(&root, "s3", "reader", 0), json!({}));
    assert_eq!(info["segments"][0]["clean"], json!(true));
    assert_eq!(info["events"], json!(9));
}

#[test]
fn check_diff_export_and_list() {
    let root = temp_root("misc");
    for s in ["a", "b"] {
        call(
            "trace_open",
            ctx(&root, s, "owner", 1),
            json!({"create": true}),
        );
    }
    call(
        "trace_append",
        ctx(&root, "a", "owner", 1),
        json!({"events": [ev("core.marker", "1"), ev("core.error", "2")]}),
    );
    call(
        "trace_append",
        ctx(&root, "b", "owner", 1),
        json!({"events": [ev("core.marker", "1")]}),
    );
    let (st, c) = call(
        "trace_check",
        ctx(&root, "a", "reader", 0),
        json!({"assertion": {"type": "cardinality", "kind": "core.marker", "min": 1, "max": 1}}),
    );
    assert_eq!(st, 0, "{c}");
    assert_eq!(c["verdict"], json!("pass"));
    let (st, d) = call(
        "trace_diff",
        ctx(&root, "a", "reader", 0),
        json!({"other": "b"}),
    );
    assert_eq!(st, 0, "{d}");
    let (st, x) = call(
        "trace_export",
        ctx(&root, "a", "reader", 0),
        json!({"name": "all"}),
    );
    assert_eq!(st, 0, "{x}");
    assert_eq!(x["events"], json!(2));
    let (_, l) = call(
        "trace_list",
        json!({"root": root.to_string_lossy()}),
        json!({}),
    );
    assert_eq!(l["count"], json!(2));
    let (_, same) = call(
        "trace_diff",
        ctx(&root, "a", "reader", 0),
        json!({"other": "b"}),
    );
    assert_eq!(d, same, "a diff is byte-deterministic");
}

#[test]
fn bad_input_is_a_status_not_a_panic() {
    let root = temp_root("bad");
    let (st, e) = call("trace_nope", json!({}), json!({}));
    assert_eq!((st, e["code"].clone()), (1, json!("unknown_command")));
    let (st, e) = call("trace_query", ctx(&root, "../x", "reader", 0), json!({}));
    assert_eq!((st, e["code"].clone()), (1, json!("bad_request")));
    let (st, e) = call("trace_query", ctx(&root, "ghost", "reader", 0), json!({}));
    assert_eq!((st, e["code"].clone()), (1, json!("not_found")));
    call(
        "trace_open",
        ctx(&root, "f", "owner", 1),
        json!({"create": true}),
    );
    let float = json!({"kind": "core.marker", "payload": {"ratio": 0.5}});
    let (st, e) = call(
        "trace_append",
        ctx(&root, "f", "owner", 1),
        json!({"events": [float]}),
    );
    assert_eq!((st, e["code"].clone()), (1, json!("bad_request")));
    // the session is still usable after the refusal
    let (st, a) = call(
        "trace_append",
        ctx(&root, "f", "owner", 1),
        json!({"events": [ev("core.marker", "ok")]}),
    );
    assert_eq!(st, 0, "{a}");
    assert_eq!(a["appended"], json!(1));
}
