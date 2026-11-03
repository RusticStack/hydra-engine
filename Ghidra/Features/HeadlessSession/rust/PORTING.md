<!--
# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
-->

# Porting notes: `ghidra_session.py` 1.1.0 client -> `hydra-client`

The Rust crate is a port of the client half of `Ghidra/Features/HeadlessSession/support/
ghidra_session.py` at `05015c8b73`: the protocol core (`_Base`, `SocketSession`, `_dial`,
`check_compatible`, `engine_protocols`, `Daemon._check_install`'s protocol check), the read path
the multi-agent benchmark uses, and the write path its direct agents use (apply/drop overlay,
edit, save, fork). The engine, its Java and its replies are not touched, and the Python client
stays the default.

## API mapping

| Python (`ghidra_session.py`) | Rust | Notes |
|---|---|---|
| `PROTOCOL`, `PROTOCOL_MIN`, `CLIENT_VERSION` | `version::PROTOCOL`, `PROTOCOL_MIN`, `CLIENT_VERSION` | 3, 2, `"1.1.0"` |
| `check_compatible(info)` | `version::check_compatible(info, client_version, protocol, protocol_min)` | same messages and codes |
| `engine_protocols(info)` | `version::engine_protocols(info)` | |
| `parse_version(text)` | `version::parse_version(text) -> Option<Vec<u64>>` | `None` where Python raises `ValueError` |
| `Daemon._check_install(ep, install)` (protocol + install) | `version::check_endpoint(ep, instance, install_dir)` | |
| `SocketSession(endpoint, client, harness, timeout, check, hello_deadline)` | `Session::connect(Endpoint, &ConnectOptions)` | TCP loopback; see "not ported" |
| `session.hello`, `.protocol`, `.endpoint` | `Session::hello`, `.protocol`, `.endpoint` | |
| `session.events`, `.on_event` | `Session::events`, `.take_events`, `.set_event_handler` | |
| `session.call(cmd, deadline=, **fields)` | `Session::call(cmd, Map, Option<f64>)` | |
| `session.call_raw(...)` | `Session::call_raw(...) -> Reply { value, raw }` | raw line only when `keep_raw` |
| `session.send`, `.wait` | `Session::send`, `.wait`, `.wait_reply` | client-chosen ids are replaced by the session's counter |
| `session.labelled(client, harness)` | `Session::labelled(..)` -> `Labelled` | see "not ported" |
| `Labelled.call/send/wait/cancel/cancel_all` | same | adds `client`, `harness`, `parallel: true`; a per-call label wins |
| `_expire` (cancel + abandon) | `wait_reply`'s timeout arm | `cancel` carries `target` and `parallel: true` |
| `session.close` | `Session::close` (or `Drop`) | shutdown, reader joined |
| `SessionError(code, message, details, trace)` | `error::SessionError` + `Error::Session` | `Display` is `"code: message"` |
| `IncompatibleError` | `Error::Session` with code `incompatible` | |
| read path: `.call("open_project", ...)` | `Session::open_project(path, Access, Discard, deadline)` | |
| `.call("open_program", ...)` | `Session::open_program(path, project, Access, overlay, deadline)` | |
| `.call("info", program=..., overlay=...)` | `Session::info(program, overlay, deadline)` | |
| `.call("functions", ...)` + paging | `Session::functions(program, offset, limit, contains, deadline)`, `functions_all` | paging loop is the benchmark's |
| `.call("decompile", ...)` | `Session::decompile(...)` | 8 optional protocol fields |
| `.call("script", script="BenchRead.java", args, program, timeout)` | `Session::script`, `Session::bench_read` | there is no `bytes` command in protocol 2; the script is the read path |
| `.call("close_project", ...)` | `Session::close_project(project, Option<Discard>, deadline)` | `None` omits `discard`, as the benchmark's read close does |
| `.call("close_program", ...)` | `Session::close_program(program, Discard, deadline)` | |
| write path: `.call("open_program", ..., overlay=, writable=, upgrade=)` | `Session::open_program`, `Session::open_program_upgrading` | a fork's writable upgrade open |
| `.call("apply_overlay", program, overlay, ops)` | `Session::apply_overlay(program, overlay, &[EditOp], deadline)` | `EditOp::Rename/Comment/Signature`; other ops through `call` |
| `.call("drop_overlay", ...)` | `Session::drop_overlay(program, overlay, deadline)` | |
| `.call("edit", program, ops)` | `Session::edit(program, &[EditOp], deadline)` | |
| `.call("save", program, comment=)` | `Session::save(program, Option<&str>, deadline)` | |
| `.call("fork_project", project, path, writable, timeout)` | `Session::fork_project(project, path, Access, Option<u64>, deadline)` | |
| `digest(obj)` in `multiagent_bench.py` | `json::digest` | Python `json.dumps(sort_keys=True)` text, SHA-256, first 24 hex |
| `decomp_hash(r)` in `multiagent_bench.py` | `json::decompile_projection` | the seven keys, `null` for absent |

## Test mapping

The Python client's own characterization tests are in
`Ghidra/Features/HeadlessSession/examples/client_compat_tests.py`. Ported:

| Python test | Rust test |
|---|---|
| `t_fake_v2_server` | `fake_v2_server_is_asked_for_3_and_the_session_says_2` |
| `t_fake_v3_server` (1.1.0 half) | `fake_v3_server_answers_3_and_keeps_the_v3_keys`, `an_engine_of_a_later_protocol_is_refused_and_closed` |
| `t_protocol_below_range` (hello half) | `a_contradictory_engine_is_refused_with_both_versions_named` |
| `t_check_compatible` | `check_compatible_table_of_accepted_answers`, `..._refused_answers`, `..._exact_protocol_form_is_one_protocol`, `an_unknown_version_answer_names_both_sides` |
| `t_endpoint_overlap` (protocol half) | `endpoint_overlap_accepts_any_overlap_of_the_range` |
| `requestedProtocol` (Java `Client.java`) | `requested_protocol_matches_the_engine_rule` |

Behavior with no Python test, characterized from `_Base`/`SocketSession` and ported:
`non_protocol_lines_and_events_do_not_become_replies`, `an_unterminated_last_line_is_still_a_reply`,
`a_closed_stream_is_a_closed_session_error`, `an_ok_false_answer_carries_the_engines_code_message_and_details`,
`a_deadline_cancels_the_request_and_the_connection_stays_usable`,
`several_threads_each_get_their_own_answer`,
`a_labelled_view_sends_its_labels_and_a_per_call_label_wins`,
`keep_raw_returns_the_engines_line_byte_for_byte`,
`a_zero_or_negative_deadline_is_refused_before_anything_is_sent`,
`reconnect_dials_a_restarted_endpoint_with_a_new_token`.

Plus unit tests for the JSON writer/SHA-256 (`json.rs`) and the spec parser (`spec.rs`).

## Not ported (out of this crate's surface)

- **The launcher.** `Install` discovery, `Launch` command/JVM options, heap policy, AOT/class
  caches, `Daemon._spawn`, `FileLock`, the registry, the `singleton` policy, the CLI — a Rust
  agent connects to a daemon that Hydralysis or the Python launcher started. The endpoint file,
  its token and the `hello` are the contract; they are all here.
- **The stdio transport (`StdioSession`).** The daemon is the multi-agent shape; a private stdio
  session is a child process with pipes and no deadline support. Protocol 2's named pipes do not
  exist in this engine: on Windows the Python client uses TCP loopback (`_dial`) exactly as this
  crate does.
- **`Labelled.__getattr__`.** Python forwards unknown attributes to the session; Rust has no such
  forwarding, so callers use the session for `protocol()`/`hello()`.
- **`last_ms` / `last_response`.** `call_raw` returns the whole response (with `ms`) instead of
  keeping a last-one field, which is racy with several threads anyway.

## Deliberate differences (flagged, not silently fixed)

1. **A malformed reply line ends the session.** Python's reader raises `ValueError` in whichever
   thread read the line; the connection stays open, the request that owned the line never gets an
   answer, and with no deadline the whole call hangs. Rust returns `Error::BadReply` and closes
   the session. This is a bug in the Python client (a hang on a server bug), preserved nowhere.
2. **A reply that is valid JSON but not an object** is `BadReply` in Rust; Python raises
   `AttributeError` (`"event" in [..]` / `m.get`). Same class of bug as 1.
3. **A response without an integer `id`** is ignored in Rust. Python stores it under
   `_pending[None]`, where it can never be matched — the same observable result, without the leak.
4. **`ok:true` without `result`**: Rust `BadReply`; Python `KeyError`. No engine answer does this.
5. **Poisoned mutexes** are recovered in Rust (`PoisonError::into_inner`); Python has no poison.
   A panic in one caller therefore does not take the session down for the others.
6. **Arbitrary-precision JSON integers.** `serde_json` refuses a number literal beyond `i64`/`u64`
   (`Error("number out of range")`); Python and Java accept it. The engine never sends one, and a
   client never sends one (ids and protocol numbers are small).
7. **Deadline validation** accepts finite `f64 > 0`; Python accepts any `int`/`float > 0`,
   including `inf` (which then never fires). Rust refuses `inf`/`NaN` up front. Error text:
   `deadline must be a positive number of seconds, not {value}` (Python uses `{value!r}`).
8. **`fields` order and separators on the wire.** Rust writes compact JSON with sorted keys;
   Python writes `json.dumps` defaults (space after `:` and `,`, insertion order). The engine
   parses both; the differential harness compares *replies*, and the reply bytes are untouched.
9. **`functions_all` stops** on a truncated page that returns 0 items; the Python paging loop
   would spin forever. The benchmark's loop trusts `returned`, so this only fires on a broken
   engine answer.

## Preserved quirks

- Request ids start at 1; `hello` consumes id 1, so the first user request is 2.
- The benchmark's fork-signature regex (`multiagent_bench.cmd_agent`) carries two literal
  backspaces where `\b` was meant, so it never matches a normal signature: the Python agent's
  `signature` op keeps `__fastcall` and the engine answers it with `__fastcall`. `hydra-agent`
  reproduces that pattern byte for byte; the reply digests depend on it.- `hello` asks for protocol 3 and carries `clientVersion`/`client`/`harness`/`token`.
- The answer's protocol is 2 or 3; `check_compatible` runs on the answer, and a failure closes
  the connection before the error is raised.
- Lines that do not start with `{` (JVM noise) are skipped; empty lines are skipped silently.
- An unterminated last line is delivered as a reply line (Python returns the `recv` tail).
- A readiness `event` read while waiting for `hello` is kept in `events`.
- Deadline expiry abandons the request id, sends `cancel` with `parallel: true`, and its
  `cancelId` is aborted too; a late answer to either is dropped.
- `deadline_exceeded.details` carries `deadlineS`, `target`, `cancelId`.
- Events are accumulated (Python's `events` list); use `take_events` to bound memory.

## Verification

```bash
cd Ghidra/Features/HeadlessSession/rust
cargo test                      # 42 tests: 19 library unit, 14 protocol, 8 agent/spec, 1 doctest
cargo clippy --all-targets -- -D warnings   # BeautifulRust lints, clean
```

Against the real engine, the lane's differential harness compares every reply with the Python
client's on the same requests (`_logs/rust-round4/rustclient/diff/`): 34/34
value- and byte-identical (27 with the per-connection client ids in `users` untouched), the same
digests, the same deadline cancellation and a working reconnect after the daemon restarts. The
full multi-agent benchmark (`.../rustclient2/bench/`) runs the 16-agent shape with the 12 direct
agents on each client: **412/412 reply keys and one digest in all nine Python/Rust/mixed runs**,
including the overlay and fork decompiles, and 0 differing keys on the same requests. The
read/query agent shape measures 2.71 vs 13.90 MB private per agent and 531 vs 698 MB tree peak.

# Porting notes: the daemon subset -> `hydra-lite`

`crates/hydra-lite` re-implements, without a JVM, the part of the Java daemon
(`ghidra.app.util.headless.session`) that `ghidra-progdb` can answer exactly. Design, refusal
protocol and measurements are in [HYDRA-LITE.md](../HYDRA-LITE.md). The rule of the port: where the
Java behaviour cannot be reproduced to the byte, the request is refused with `use_full_daemon`;
there is no approximation.

| Java | Rust | Notes |
|---|---|---|
| `Connection` (line reading, `MAX_LINE_BYTES`, `authenticate`, `annotate`, dispatch order) | `engine::Connection`, `server::read_line_limited` | `ms` 0 for pre-dispatch errors; `wait` read before the command for the slot-taking commands and after project selection for the others; `parallel` / `ordered` validated before dispatch |
| Gson output (`JsonObject.toString`) | `json` | compact, insertion order, nulls written, ` `/` ` escaped and HTML characters left alone (HTML escaping off, as the daemon configures Gson), numbers keep their source text; strict parser, anything lenient is `unparsable_request` |
| `Caller.of`, `MAX_LABEL` 128 | `request::Request::label` | |
| `HeadlessSession` (instance lock, endpoint file, token, idle loop, reaper) | `server` | endpoint file via temporary file and rename, trailing newline; reaper lap clamp(keepWarm/4, 1 s .. 15 s) |
| `hello` (`protocolMin/Max`, capabilities, limits, policy, paths, analysisIdentity) | `identity` | learned from a running Java daemon, cached in the `hydra-front` identity file |
| `ProjectResolver`, `ProjectFormat`, `Revision`, `ProjectData` index / `.prp` / `db.N.gbf` | `project` | refuses sweep-pending staging files, fork sidecars, versioned items, non-Program items, more than 64 programs; SHA-256 revisions over file keys |
| `ConcurrentHashMap` iteration order of the project map | `javaish::ChmOrder` | bins ascending, transfer splits with the `lastRun` rule, resize at 12 then 0.75 n; refuses when the order is inexact (a bin of 8) |
| `HashMap` order of file names, `TreeSet` of folders | `javaish` | refuses on a bucket collision |
| `ProgramView` facts, `functions` | `program` | via `ghidra_progdb::query::Program::open_lazy`; refuses mapped or non-RAM blocks, namespaced or unnamed functions, other languages and format versions |
| `SessionException` codes and messages | `error::SessionError` | word for word |
| none | `error::Refusal`, `Reason` | the `use_full_daemon` error |

Verification: `cargo test -p hydra-lite` (34 tests), `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check -p hydra-lite`, and `examples/reply_parity.py lite` (78 requests identical to
the Java daemon, key order and raw bytes included; 16 refusal probes). The workspace's
`cargo fmt --check` also reports formatting differences in `hydra-client` and `hydra-agent`; they
predate this crate and are not touched here.

Clients: a lite daemon is only useful when the clients follow its refusal. `ghidra_session.py` and
`hydra-client` (`lite.rs`: `LiteMode`, `FullDaemon`, `PythonLauncher`; `session.rs`: the replay of
the state commands and the re-send of the unanswered requests) do, per HYDRA-LITE.md, "Clients".
`hydra-client` has no launcher, so `PythonLauncher` runs `ghidra_session.py ... ensure` for the
`<instance>.full` daemon. Tests: `crates/hydra-client/tests/lite_failover.rs` (a fake lite and a fake
full daemon), `examples/cc_lite.py` (the same for Python), `reply_parity.py auto [--agent]`.
