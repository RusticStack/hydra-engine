//! Privacy and honesty gates (WS-I, spec 14.6 and 14.13), driven through the request service and
//! the files it leaves on disk, as an attacker or an exporting user would see them:
//!
//! - secret-like strings are absent from previews, replies, the index, the segments, the manifest,
//!   the key directory's listing, exports and the tool's own stdout/stderr;
//! - keyed ids do not link across scopes, and two sessions only correlate when a scope is shared on
//!   purpose (out of band: the same key directory and scope name);
//! - payload artifacts stay out of an export unless authorized, and an eviction writes a tombstone
//!   and changes the bundle a later export produces;
//! - a retention budget refusal is explicit: every submitted event is accounted for as accepted,
//!   dropped-by-budget (with a `core.capture.gap`) or rejected with a reason.

use hydra_trace::artifact::ArtifactSpec;
use hydra_trace::corrid::KeyRing;
use hydra_trace::service::Service;
use hydra_trace::session::Session;
use hydra_trace::store::Options;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Strings a policy must never let through. The first three are shapes `redacted_preview` masks;
/// the fourth is a bare random-looking secret the keyed id replaces entirely when no preview is
/// allowed.
const SECRETS: [&str; 4] = [
    "hunter2-ZZSECRET-ONE",
    "ABCDEFGH12345678abcdefghSECRETTWO",
    "XQ9TL0MNOP4RSTUVWXYZ5SECRETTHREE",
    "tail-secret-FOUR-0123456789",
];

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hydra-privacy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn call(svc: &Service, command: &str, request: &Value) -> Value {
    let bytes = svc.handle(command, &serde_json::to_vec(request).unwrap());
    serde_json::from_slice(&bytes).unwrap()
}

fn event(seq: u64, kind: &str, payload: Value) -> Value {
    json!({
        "kind": kind, "source_id": "priv", "source_seq": seq, "producer_gen": 1,
        "clock_domain": "c", "t_mono_ns": 1000 + seq, "confidence": "exact",
        "process_id": 7, "thread_id": 1, "payload": payload,
    })
}

/// Events whose payload strings carry the secrets in the forms a hook would see them.
fn secret_events() -> Vec<Value> {
    vec![
        event(
            0,
            "core.resource.open",
            json!({"type": "file", "key": "res/a",
                "path": {"$string": format!("C:\\Users\\x\\config.ini password={}", SECRETS[0])}}),
        ),
        event(
            1,
            "core.resource.open",
            json!({"type": "file", "key": "res/b",
                "path": {"$string": format!("login token: {} for the service", SECRETS[1])}}),
        ),
        event(
            2,
            "core.resource.open",
            json!({"type": "file", "key": "res/c",
                "path": {"$string": format!("opened {} today", SECRETS[2])}}),
        ),
        event(
            3,
            "core.resource.open",
            json!({"type": "file", "key": "res/d",
                "nested": {"deep": [{"$string": format!("api_key={}", SECRETS[3])}]}}),
        ),
    ]
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Every byte of every file below `dir` (including the SQLite WAL and shared-memory files), and
/// every file name, must be free of `needles`.
fn assert_tree_free_of(dir: &Path, needles: &[&str], what: &str) {
    let mut files = Vec::new();
    files_under(dir, &mut files);
    assert!(!files.is_empty(), "{what}: nothing to scan under {dir:?}");
    for f in files {
        let name = f.to_string_lossy().to_string();
        let bytes = std::fs::read(&f).unwrap_or_default();
        for needle in needles {
            assert!(!name.contains(needle), "{what}: {name} names a secret");
            let n = needle.as_bytes();
            assert!(
                !bytes.windows(n.len()).any(|w| w == n),
                "{what}: {name} contains the secret {needle:?}"
            );
        }
    }
}

fn assert_text_free_of(text: &str, needles: &[&str], what: &str) {
    for needle in needles {
        assert!(!text.contains(needle), "{what} contains {needle:?}");
    }
}

fn find_all<'a>(v: &'a Value, key: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == key {
                    out.push(x);
                }
                find_all(x, key, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| find_all(x, key, out)),
        _ => {}
    }
}

/// The payload text of every query row (rows carry the payload as a JSON string).
fn row_payloads(reply: &Value) -> Vec<Value> {
    reply["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| serde_json::from_str(r["payload"].as_str().unwrap()).unwrap())
        .collect()
}

fn corr_ids(payloads: &[Value]) -> Vec<String> {
    let mut found = Vec::new();
    for p in payloads {
        let mut ids = Vec::new();
        find_all(p, "corr_id", &mut ids);
        found.extend(ids.iter().map(|v| v.as_str().unwrap().to_string()));
    }
    found
}

fn run_all_readers(svc: &Service, session: &str) -> String {
    // Every read-side command a client can make, concatenated, so one scan covers them all.
    let mut all = String::new();
    for req in [
        json!({"session": session, "limit": 1000}),
        json!({"session": session, "group_by": "kind"}),
        json!({"session": session, "group_by": "resource"}),
        json!({"session": session, "with_symbols": true, "limit": 1000}),
    ] {
        all.push_str(&call(svc, "trace_query", &req).to_string());
    }
    all.push_str(&call(svc, "trace_info", &json!({"session": session})).to_string());
    all.push_str(&call(svc, "trace_list", &json!({})).to_string());
    all.push_str(
        &call(
            svc,
            "trace_check",
            &json!({"session": session, "persist": false,
                "assertions": [{"type": "forbidden", "kind": "core.error", "name": "none"}]}),
        )
        .to_string(),
    );
    all
}

#[test]
fn secret_like_strings_are_absent_from_previews_replies_index_segments_and_exports() {
    for allow_preview in [false, true] {
        let tag = if allow_preview {
            "preview"
        } else {
            "nopreview"
        };
        let root = scratch(tag);
        let svc = Service::new(&root);
        let open = call(
            &svc,
            "trace_open",
            &json!({"session": "s", "preview": allow_preview}),
        );
        assert_eq!(open["ok"], true, "{open}");
        let appended = call(
            &svc,
            "trace_append",
            &json!({"session": "s", "events": secret_events()}),
        );
        assert_eq!(appended["accepted"], 4, "{appended}");
        assert_eq!(appended["strings_keyed"], 4, "{appended}");
        assert!(appended["rejected"].as_array().unwrap().is_empty());

        // Replies
        let replies = run_all_readers(&svc, "s");
        assert_text_free_of(&replies, &SECRETS, "a reply");
        let page = call(&svc, "trace_query", &json!({"session": "s", "limit": 100}));
        let payloads = row_payloads(&page);
        assert_eq!(
            corr_ids(&payloads).len(),
            4,
            "every string became a keyed id"
        );
        let mut previews = Vec::new();
        for p in &payloads {
            find_all(p, "preview", &mut previews);
        }
        if allow_preview {
            // A control: previews exist, are bounded, and show the harmless words only.
            assert_eq!(previews.len(), 4, "policy allows previews: {payloads:?}");
            let joined: Vec<&str> = previews.iter().map(|v| v.as_str().unwrap()).collect();
            assert!(joined.iter().all(|p| p.len() <= 256));
            assert!(
                joined.iter().any(|p| p.contains("config.ini ***")),
                "{joined:?}"
            );
            assert!(
                joined.iter().any(|p| p.contains("login token:***")),
                "{joined:?}"
            );
            assert!(
                joined.iter().any(|p| p.contains("opened *** today")),
                "{joined:?}"
            );
            assert!(
                joined.iter().all(|p| p.contains("***")),
                "every secret masked: {joined:?}"
            );
        } else {
            assert!(
                previews.is_empty(),
                "no preview unless the policy allows one"
            );
        }

        // The writer's files, with the writer still open (WAL and shm present)
        assert_tree_free_of(&root, &SECRETS, tag);
        call(&svc, "trace_close", &json!({"session": "s"}));
        assert_tree_free_of(&root, &SECRETS, tag);

        // Exports, with and without payload authorization
        let out = root.join("out-export");
        let exp = call(
            &svc,
            "trace_export",
            &json!({"session": "s", "out": out.to_string_lossy(), "exported_at": "t"}),
        );
        assert_eq!(exp["ok"], true, "{exp}");
        assert_text_free_of(&exp.to_string(), &SECRETS, "the export reply");
        assert_tree_free_of(&out, &SECRETS, "export");

        // The tool's own stdout/stderr (its logs) for an import of the same events
        let input_dir = scratch(&format!("input-{tag}"));
        let jsonl = input_dir.join("secret.jsonl");
        let lines: Vec<String> = secret_events().iter().map(Value::to_string).collect();
        std::fs::write(&jsonl, lines.join("\n") + "\n").unwrap();
        let cli_root = root.join("cli");
        let run = |args: &[&str]| {
            let o = Command::new(env!("CARGO_BIN_EXE_hydra-trace"))
                .args(args)
                .output()
                .unwrap();
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), text)
        };
        let (ok, log) = run(&[
            "import",
            cli_root.to_str().unwrap(),
            "c",
            jsonl.to_str().unwrap(),
        ]);
        assert!(ok, "{log}");
        assert_text_free_of(&log, &SECRETS, "the import log");
        let (ok, log) = run(&["verify", cli_root.to_str().unwrap(), "c"]);
        assert!(ok, "{log}");
        assert_text_free_of(&log, &SECRETS, "the verify log");
        let cli_out = root.join("cli-export");
        let (ok, log) = run(&[
            "export",
            cli_root.to_str().unwrap(),
            "c",
            cli_out.to_str().unwrap(),
        ]);
        assert!(ok, "{log}");
        assert_text_free_of(&log, &SECRETS, "the export log");
        assert_tree_free_of(&cli_root, &SECRETS, "cli store");
        assert_tree_free_of(&cli_out, &SECRETS, "cli export");

        // A client's own rejected event must not echo the string back either
        let bad = call(
            &svc,
            "trace_open",
            &json!({"session": "s2", "preview": allow_preview}),
        );
        assert_eq!(bad["ok"], true);
        let rejected = call(
            &svc,
            "trace_append",
            &json!({"session": "s2", "events": [
                {"kind": "not a kind", "source_id": "priv", "source_seq": 0, "producer_gen": 1,
                 "clock_domain": "c", "t_mono_ns": 1, "confidence": "exact",
                 "payload": {"path": {"$string": format!("password={}", SECRETS[0])}}}
            ]}),
        );
        assert_text_free_of(&rejected.to_string(), &SECRETS, "a rejection reply");
        assert_tree_free_of(&root, &SECRETS, "after a rejection");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(input_dir);
    }
}

#[test]
fn keyed_ids_are_stable_in_a_scope_and_unlinkable_across_scopes() {
    let root = scratch("scopes");
    let svc = Service::new(&root);
    let same_text = json!({"type": "file", "key": "k", "path": {"$string": SECRETS[0]}});
    let mut ids = Vec::new();
    for session in ["alpha", "beta"] {
        call(&svc, "trace_open", &json!({"session": session}));
        // Twice in one session: the same value in the same scope is the same id.
        let r = call(
            &svc,
            "trace_append",
            &json!({"session": session, "events": [
                event(0, "core.resource.open", same_text.clone()),
                event(1, "core.resource.open", same_text.clone()),
            ]}),
        );
        assert_eq!(r["accepted"], 2, "{r}");
        let page = call(
            &svc,
            "trace_query",
            &json!({"session": session, "limit": 10}),
        );
        let found = corr_ids(&row_payloads(&page));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], found[1], "same scope, same value, same id");
        ids.push(found[0].clone());
        // The scope is recorded with the id and names the session
        let mut scopes = Vec::new();
        for p in row_payloads(&page) {
            let mut s = Vec::new();
            find_all(&p, "scope", &mut s);
            scopes.extend(s.iter().map(|v| v.as_str().unwrap().to_string()));
        }
        assert!(scopes.iter().all(|s| *s == format!("session:{session}")));
    }
    assert_ne!(ids[0], ids[1], "two sessions must not correlate by default");

    // The key never reaches a reply or an export: scan the key bytes against everything exposed.
    let mut key_files = Vec::new();
    files_under(&root.join("alpha").join("keys"), &mut key_files);
    assert_eq!(key_files.len(), 1, "one key file for the one scope");
    let key_hex = std::fs::read_to_string(&key_files[0]).unwrap();
    let key_hex = key_hex.trim();
    assert_eq!(key_hex.len(), 64);
    call(&svc, "trace_close", &json!({"session": "alpha"}));
    let out = root.join("export-alpha");
    let exp = call(
        &svc,
        "trace_export",
        &json!({"session": "alpha", "out": out.to_string_lossy(), "exported_at": "t"}),
    );
    assert_eq!(exp["ok"], true);
    assert_text_free_of(&exp.to_string(), &[key_hex], "the export reply");
    assert_tree_free_of(&out, &[key_hex], "the export");
    assert_text_free_of(&run_all_readers(&svc, "alpha"), &[key_hex], "a reply");

    // A key directory from another install derives different ids for the same text and scope.
    let mut other = KeyRing::open(scratch("scopes-other-install").join("keys")).unwrap();
    let theirs = other
        .derive("session:alpha", SECRETS[0].as_bytes())
        .unwrap();
    assert_ne!(theirs, ids[0]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_session_correlation_needs_an_explicitly_shared_scope() {
    let d = scratch("shared");
    // Explicitly shared: one key directory and one named scope, provisioned out of band.
    let mut a = KeyRing::open(d.join("shared-keys")).unwrap();
    let mut b = KeyRing::open(d.join("shared-keys")).unwrap();
    let ida = a.derive("shared:team-1", SECRETS[0].as_bytes()).unwrap();
    let idb = b.derive("shared:team-1", SECRETS[0].as_bytes()).unwrap();
    assert_eq!(ida, idb, "a shared scope correlates");
    // A different scope name over the same directory still does not.
    let idc = b.derive("shared:team-2", SECRETS[0].as_bytes()).unwrap();
    assert_ne!(ida, idc);
    // Different values never collide in a scope.
    assert_ne!(
        ida,
        a.derive("shared:team-1", SECRETS[1].as_bytes()).unwrap()
    );
    assert_eq!(ida.len(), 32);
    let _ = std::fs::remove_dir_all(d);
}

fn put_session_with_artifact(
    root: &Path,
    id: &str,
    payload: &[u8],
    retention: Option<u64>,
) -> String {
    let (mut s, _) = Session::open(root, id, Options::default()).unwrap();
    let spec = ArtifactSpec {
        scope: "packet".into(),
        max_bytes: 1024,
        retention_secs: retention,
        redact: vec![],
    };
    let art = s.artifacts();
    let dir_clone =
        hydra_trace::artifact::Artifacts::open(hydra_trace::artifact::dir_of(s.dir())).unwrap();
    let _ = art;
    let aid = dir_clone.put(s.store_mut(), payload, &spec, 1000).unwrap();
    let r = s
        .append(&[event(
            0,
            "core.resource.read",
            json!({"type": "file", "key": "k", "artifact": aid}),
        )])
        .unwrap();
    assert_eq!(r.accepted, 1);
    aid
}

#[test]
fn payload_artifacts_are_excluded_from_export_unless_authorized() {
    let root = scratch("payload");
    let private = b"PRIVATE-PAYLOAD-BYTES-0xC0FFEE";
    let aid = put_session_with_artifact(&root, "p", private, None);
    let svc = Service::new(&root);

    let denied = root.join("denied");
    let r = call(
        &svc,
        "trace_export",
        &json!({"session": "p", "out": denied.to_string_lossy(), "exported_at": "t"}),
    );
    assert_eq!(r["ok"], true, "{r}");
    assert!(r["artifacts_included"].as_array().unwrap().is_empty());
    assert!(
        r["not_reproducible"]
            .as_array()
            .unwrap()
            .contains(&json!({"artifact": aid, "limitation": "payload-not-authorized"})),
        "{r}"
    );
    assert_tree_free_of(&denied, &["PRIVATE-PAYLOAD-BYTES"], "unauthorized export");

    // Authorizing some other id does not authorize this one.
    let other = root.join("other");
    let r = call(
        &svc,
        "trace_export",
        &json!({"session": "p", "out": other.to_string_lossy(), "exported_at": "t",
            "authorized_artifacts": ["art_not_this_one"]}),
    );
    assert!(
        r["artifacts_included"].as_array().unwrap().is_empty(),
        "{r}"
    );
    assert_tree_free_of(
        &other,
        &["PRIVATE-PAYLOAD-BYTES"],
        "export authorizing another id",
    );

    // The bytes exist locally, in the session's private artifact store
    let local = std::fs::read(root.join("p").join("artifacts").join(format!("{aid}.bin"))).unwrap();
    assert_eq!(local, private);

    let allowed = root.join("allowed");
    let r = call(
        &svc,
        "trace_export",
        &json!({"session": "p", "out": allowed.to_string_lossy(), "exported_at": "t",
            "authorized_artifacts": [aid]}),
    );
    assert_eq!(r["artifacts_included"], json!([aid]), "{r}");
    let exported = std::fs::read(allowed.join(format!("traces/artifacts/{aid}.bin"))).unwrap();
    assert_eq!(exported, private);
    // Authorization changes the bundle: the two exports are different evidence
    let id_denied: Value =
        serde_json::from_slice(&std::fs::read(denied.join("manifest.json")).unwrap()).unwrap();
    let id_allowed: Value =
        serde_json::from_slice(&std::fs::read(allowed.join("manifest.json")).unwrap()).unwrap();
    assert_ne!(id_denied["bundle_id"], id_allowed["bundle_id"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retention_eviction_writes_a_tombstone_and_changes_the_dependent_bundle() {
    let root = scratch("evict");
    let aid = put_session_with_artifact(&root, "e", b"EVICTABLE-PAYLOAD", Some(60));
    let svc = Service::new(&root);
    let export = |name: &str| -> (Value, PathBuf) {
        let out = root.join(name);
        let r = call(
            &svc,
            "trace_export",
            &json!({"session": "e", "out": out.to_string_lossy(), "exported_at": "t",
                "authorized_artifacts": [aid.clone()]}),
        );
        assert_eq!(r["ok"], true, "{r}");
        (r, out)
    };
    let (before, before_dir) = export("before");
    assert_eq!(before["artifacts_included"], json!([aid]));
    hydra_trace::export::verify(&before_dir).unwrap();

    // Retention runs out: the bytes go, a tombstone stays
    let mut reopened = Session::open(&root, "e", Options::default()).unwrap().0;
    let arts =
        hydra_trace::artifact::Artifacts::open(hydra_trace::artifact::dir_of(reopened.dir()))
            .unwrap();
    assert!(
        arts.evict_expired(reopened.store_mut(), 1059)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        arts.evict_expired(reopened.store_mut(), 1060).unwrap(),
        vec![aid.clone()]
    );
    drop(reopened);
    assert!(
        !root
            .join("e")
            .join("artifacts")
            .join(format!("{aid}.bin"))
            .exists()
    );

    let (after, after_dir) = export("after");
    assert!(
        after["artifacts_included"].as_array().unwrap().is_empty(),
        "{after}"
    );
    assert!(
        after["not_reproducible"]
            .as_array()
            .unwrap()
            .contains(&json!({"artifact": aid, "limitation": "artifact-evicted"})),
        "{after}"
    );
    assert_ne!(
        before["bundle_id"], after["bundle_id"],
        "the dependent bundle is a different one"
    );
    let tombstones: Value =
        serde_json::from_slice(&std::fs::read(after_dir.join("traces/tombstones.json")).unwrap())
            .unwrap();
    let t = tombstones.as_array().unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0]["id"], aid);
    assert_eq!(t[0]["reason"], "retention-expired");
    assert_tree_free_of(&after_dir, &["EVICTABLE-PAYLOAD"], "export after eviction");
    // A caller cannot name it as authorized to get it back
    assert!(
        !after_dir
            .join(format!("traces/artifacts/{aid}.bin"))
            .exists()
    );
    // The earlier bundle is still internally consistent: it is a copy the owner already holds,
    // and it names the pre-eviction revision, so it can be told apart from the post-eviction one.
    hydra_trace::export::verify(&before_dir).unwrap();
    hydra_trace::export::verify(&after_dir).unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_retention_budget_refusal_is_explicit_and_accounts_for_every_event() {
    for (max_events, submitted) in [(5u64, 20u64), (0, 8)] {
        let root = scratch(&format!("budget{max_events}"));
        let svc = Service::new(&root);
        let open = call(
            &svc,
            "trace_open",
            &json!({"session": "b", "max_events": max_events}),
        );
        assert_eq!(open["ok"], true, "{open}");
        let events: Vec<Value> = (0..submitted)
            .map(|i| {
                event(
                    i,
                    "core.resource.open",
                    json!({"type": "file", "key": format!("k{i}")}),
                )
            })
            .collect();
        let r = call(
            &svc,
            "trace_append",
            &json!({"session": "b", "events": events}),
        );
        assert_eq!(r["ok"], true, "{r}");
        let accepted = r["accepted"].as_u64().unwrap();
        let dropped = r["dropped_budget"].as_u64().unwrap();
        let rejected = r["rejected"].as_array().unwrap().len() as u64;
        assert_eq!(
            accepted + dropped + rejected,
            submitted,
            "every submitted event is accounted for: {r}"
        );
        assert!(
            dropped > 0,
            "the budget was reached and the reply says so: {r}"
        );

        // The session says it stopped, and the stop is an event a reader can find
        let info = call(&svc, "trace_info", &json!({"session": "b"}));
        assert_eq!(info["stopped"], true, "{info}");
        assert!(
            info["gaps"].to_string().contains("budget"),
            "the gap table names the budget: {info}"
        );
        let gaps = call(
            &svc,
            "trace_query",
            &json!({"session": "b", "kinds": ["core.capture.gap"], "limit": 10}),
        );
        let rows = gaps["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "exactly one stop marker: {gaps}");
        assert!(rows[0]["payload"].as_str().unwrap().contains("budget"));

        // Later appends stay refused and counted, never silently lost
        let more = call(
            &svc,
            "trace_append",
            &json!({"session": "b", "events": [event(submitted, "core.resource.open", json!({"type": "file", "key": "late"}))]}),
        );
        assert_eq!(more["accepted"], 0, "{more}");
        assert_eq!(more["dropped_budget"], 1, "{more}");

        // A check over a stopped session cannot claim a clean pass over the missing events
        let check = call(
            &svc,
            "trace_check",
            &json!({"session": "b", "persist": false,
                "assertions": [{"type": "forbidden", "kind": "core.error", "name": "no-errors"}]}),
        );
        let verdict = check["results"][0]["verdict"].as_str().unwrap().to_string();
        assert_ne!(
            verdict, "pass",
            "a stopped capture must not read as a clean pass: {check}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn partial_results_name_their_limits() {
    // trace_explain over a bounded budget says it truncated
    let root = scratch("partial");
    let svc = Service::new(&root);
    call(&svc, "trace_open", &json!({"session": "x"}));
    let events: Vec<Value> = (0..50)
        .map(|i| {
            event(
                i,
                "core.state.write",
                json!({"object": 1, "key": "hp", "new": i}),
            )
        })
        .collect();
    let r = call(
        &svc,
        "trace_append",
        &json!({"session": "x", "events": events}),
    );
    assert_eq!(r["accepted"], 50, "{r}");
    let page = call(&svc, "trace_query", &json!({"session": "x", "limit": 10}));
    assert!(
        page["next"].is_number(),
        "a short page hands back a cursor: {page}"
    );
    assert_eq!(page["up_to"], 50, "and the snapshot pin it read at: {page}");
    let rest = call(
        &svc,
        "trace_query",
        &json!({"session": "x", "limit": 100, "after": page["next"], "up_to": page["up_to"]}),
    );
    assert_eq!(
        rest["rows"].as_array().unwrap().len(),
        40,
        "paging loses nothing: {rest}"
    );
    assert!(rest["next"].is_null());
    let _ = std::fs::remove_dir_all(root);
}
