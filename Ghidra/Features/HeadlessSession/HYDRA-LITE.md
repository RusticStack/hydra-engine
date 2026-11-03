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

# `hydra-lite`: a JVM-free, read-only Hydra Engine daemon

STATUS: PROTOTYPE, opt-in, not the default and not wired into `build-install.py`. The Java daemon
is unchanged and stays the only complete implementation. `hydra-lite` answers a small subset of
protocol 3 with the Java daemon's reply bytes and refuses everything else with a structured error
that means "ask the full daemon". It never guesses.

Crate: `rust/crates/hydra-lite` (library `hydra_lite`, binary `hydra-lite`). Program databases are
read by `ghidra-progdb` (`Ghidra/Framework/HydraFormats`), the Rust port of the Program database
reader; this crate adds the project layer, the session state and the protocol.

## What it answers

Protocol 3, over the loopback TCP endpoint the Java daemon publishes, for read-only projects whose
programs are x86:LE:64 databases of the current format:

| command | notes |
| --- | --- |
| `hello` | the v3 block (`protocolMin/Max`, `capabilities`, `limits`, `policy`, `paths`, `platform`, `analysisIdentity`) comes from the learned identity; live fields (`pid`, `uptimeMs`, `listen`, `memory`, `projects`) are the lite process's own |
| `ping` | |
| `projects`, `programs` | the `ConcurrentHashMap` iteration order of the Java daemon is modelled; where it cannot be modelled exactly the answer is refused (`inexact_value`) |
| `open_project`, `close_project`, `project` | read-only only; ids `p1`, `p2`, ... as in Java; the program entries linger after the last user leaves and are reaped as `keepWarm` says |
| `list` | folders and files, paging, `programsOnly`, `metadata`, `sha256`; the index and the stored files are read afresh on every request, as Java does |
| `open_program`, `switch`, `info`, `close_program` | read-only; `info` carries the program facts (language, compiler, image base, format, executable, hashes, function count, analysed) |
| `functions` | functions whose entry lies in a RAM block, address order, `limit`, `offset`, `contains` (substring) |
| `shutdown` | `force` as in Java |

The Java daemon has no `function_at`, `symbols`, `xrefs`, `bytes` or data type command; those
queries exist in `ghidra-progdb` (`query::Program`) but there is nothing in protocol 3 to speak
them with, so `hydra-lite` does not invent any. Comments, bookmarks and equates are likewise not
commands of the daemon.

Errors the Java daemon gives for these commands (`no_project`, `no_program`, `not_found`,
`bad_request`, `unauthorized`, ...) are reproduced word for word, including `ms` (0 for
pre-dispatch errors) and the order in which the Java daemon checks a request.

## The refusal: `use_full_daemon`

Anything `hydra-lite` cannot reproduce exactly gets this reply and nothing else:

```json
{"id":7,"ok":false,"error":{"code":"use_full_daemon","message":"...","details":{"reason":"unsupported_command","cmd":"decompile"}},"ms":0}
```

`error.code` is the constant `use_full_daemon`. It is new: it is not in PROTOCOL-3.md and the Java
daemon never sends it. `error.details.reason` is one of a closed set, and `details.cmd` is the
command of the request (absent for a refusal that has no request, see `capacity`). `ms` is 0.
A client that reads `use_full_daemon` closes the connection, starts or joins the full daemon of the
same instance with `GHIDRA_SESSION_FRONT` unset, and sends its session again from the beginning
(`hello`, `open_project`, ...). The shipped clients (`ghidra_session.py`, `hydra-client`) do not do
this yet; the code is defined so that they can, and the harness below shows what they would see.

| reason | meaning |
| --- | --- |
| `unsupported_command` | not in the table above (`decompile`, `status`, `health`, `cancel`, `overlays`, `journal`, `script`, `import`, every write, every `trace_*`, an unknown name) |
| `unsupported_request` | a command it has, with something it leaves out: `writable`, `share`, `overlay`, `regex`, `parallel`, a write-class option |
| `unparsable_request` | the line is not one strict JSON object (Gson would accept some such lines; reading them differently would be a guess) |
| `inexact_value` | a number, name or order it cannot read the way Java does (a path that is not canonical, a hash-order bucket collision it cannot order, a project-id order it cannot model) |
| `diverged_connection` | an earlier refusal on this connection: the full daemon holds state this process does not, so from then on only `ping` and `hello` are answered; everything else gets this reason |
| `no_identity` | the identity cache does not cover this request (see Identity) |
| `unsupported_project` | the project cannot be presented exactly: a fork sidecar, a sweep-pending staging file or lock, a versioned item, an item that is not a Program, more than 64 programs, a layout it does not know |
| `unsupported_program` | the program cannot be presented exactly: not DB version 33 / data type version 3, not `x86:LE:64:default` version 4.9, mapped or non-RAM memory blocks, functions in namespaces, unnamed functions, options of an unexpected type |
| `capacity` | `--workers` connections (default 64) are being served; see below |
| `unsupported_engine` | the identity's `ghidraVersion` is not `12.3`, the release the format constants were checked against |

`capacity` is answered by the acceptor before any request is read, so the reply has no `id` and no
`details.cmd`; the connection is closed after it:

```json
{"ok":false,"error":{"code":"use_full_daemon","message":"3 connections are served already; use the full daemon","details":{"reason":"capacity"}},"ms":0}
```

## Deployment

```
set GHIDRA_SESSION_FRONT=<path>\hydra-lite.exe
set GHIDRA_SESSION_FRONT_OPTS=--workers 64        (optional)
```

The launcher then runs `hydra-lite [opts] -- <the Java command line>`, exactly as it does for
`hydra-front` (FRONT-DOOR.md). `hydra-lite` reads `-stateDir`, `-instance`, `-idleTimeout` and
`-keepWarm` from that command line and does the rest the way the Java daemon does:

* takes the instance lock `STATE/INSTANCE.lock`;
* listens on `127.0.0.1`, port chosen by the system;
* writes the endpoint file `STATE/INSTANCE.json` atomically, with a trailing newline: the identity
  endpoint (`protocol`, `protocolMin/Max`, `ghidra`, `ghidraVersion`, `hydraVersion`, `installId`,
  `minClient`, `install`, `java`, `launch`, `project`, `writable`) with the live `pid`, `host`,
  `port`, a fresh 256-bit `token`, `started` and `instance`;
* requires `hello` with that token as the first request (`unauthorized`, `ms` 0, then close);
* exits when no client has been connected for `-idleTimeout` seconds (0: never; checked: 3 s,
  exit 3.0 s after the last client left, none while one stays connected), or after `shutdown`,
  and removes the endpoint file (checked: gone 0.26 s after `shutdown`).

There is no named pipe: the Java daemon publishes TCP only, so `hydra-lite` does too.

### Identity

`hello` carries values only the engine knows (build ids, capabilities, limits, the decompiler hash).
`hydra-lite` does not invent them: it learns them from a running Java daemon of the same install and
keeps them in `STATE/INSTANCE.front-identity.json`, the cache `hydra-front` uses (same name, same
key: FNV-1a of the Java command line, so the two share one file).

```
hydra-lite learn --from STATE/INSTANCE.json -- <the Java command line>
```

sends a protocol 3 `hello` to the running daemon and stores the answer (it retries while the
decompiler hash is still being computed). Without a cache for the command line `hydra-lite` refuses
to start (exit 2, "no learned identity"). A cache for another Ghidra release than `12.3` is not
used (`unsupported_engine`). `reply_parity.py lite` does the sequence the way a deployment would:
start the launcher once (it fails), learn from a running Java daemon with the command line the
launcher used, start again.

## Concurrency

One thread per connection, at most `--workers` at a time (default 64), each thread handling its
connection's requests in order; the session state sits behind one lock held only while a request
touches it, never across file reads. Replies on one connection are therefore always in request
order. The Java daemon may answer overlapping `parallel` requests out of order; `hydra-lite`
refuses `"parallel":true` rather than choose an order.

## Not reproduced, therefore refused or absent

* The Governor's capacity and heap refusals, lane scheduling, `queue` / `stale` / `refreshed`
  annotations beyond what an idle daemon gives (`stale` and `refreshed` follow the rule for
  non-inline commands; nothing else is modelled), `cancel`, `status`, `health`.
* Forks, overlays, writable opens, locks, the upgrade cache, `refresh` / `reopen`, the journal.
* Gson's lenient parsing (refused as `unparsable_request`), a request line longer than 64 MiB
  (the same `bad_request` as Java, then close; the client may see the connection reset before it
  reads the reply when megabytes are unread, as with Java).
* Anything depending on the JVM: default thread names, GC figures (`hello.memory` is the lite
  process's working set and peak working set).

## Gates

* `cargo test -p hydra-lite` (34 tests: the JSON writer and parser against Gson's output rules,
  the `ConcurrentHashMap` order model, the project and program checks, request validation,
  dispatch order, the identity cache), `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check -p hydra-lite`.
* `examples/reply_parity.py lite --ghidra INSTALL --work EMPTYDIR --lite hydra-lite.exe`:
  builds the fixture project (alpha, beta and the non-contiguous frag), runs one corpus (session
  errors, open/list/info/functions in every variant the lite set has, two projects, a second
  client joining and leaving, error cases of every kind) against a Java daemon and against
  `hydra-lite` started through `GHIDRA_SESSION_FRONT` (the harness checks the answering process is
  `hydra-lite`), and fails on any difference. Two comparisons: the masked replies of
  `reply_parity.py` with the key order kept (the plain `compare` ignores order), and the raw reply
  lines with only the request id, timings and the work directory replaced, which includes the
  unmasked revisions, byte counts, hashes and timestamps. Then 16 requests the lite set must not
  answer (unknown command, `status`, `decompile`, a writable open, `regex`, `overlay`, `parallel`,
  an older program format, ...) must each get `use_full_daemon` with a reason, after which the
  connection must answer `info` with `diverged_connection` and `ping` normally.
  Last run (`_logs/h7/fmt/lite-parity2.log`): 78 requests, 0 refused where Java answers, 0
  differences, 16 of 16 refusals right.
* `examples/lite_bench.py`: the measurements below.

## Measurements

Windows 11, 24 logical processors, release build, Java 25.0.4 with the install's class cache warm
(`launch.mode` `fast`), the fixture project (3 programs of 1.2 MB, 3 functions each), the install's
own Python client for both daemons, 100 repetitions per command, 16 client processes (not threads: a
Python process serialises its threads on the interpreter lock and would measure itself). Figures
are one run on one machine (`_logs/h7/fmt/lite-bench3.log`, JSON beside it); the run to run
spread of the Java start-up is some 10 percent. Do not read them as constants.

| | Java daemon | hydra-lite |
| --- | --- | --- |
| spawn to first `hello` answer, through the Python launcher | 827 ms | 95 ms |
| plus `open_project`, `open_program`, `functions` | 1665 ms | 37 ms |
| spawn to first `functions` answer | 2492 ms | 132 ms |
| spawn to first `hello` answer, bare process (endpoint file polled, raw socket, 15 runs) | not measured | median 35 ms (19 to 170) |
| working set idle after the first `functions` (peak) | 290 MB (300) | 5.8 MB (6.7) |
| working set with 16 clients, each with the program open (peak) | 961 MB (989) | 10.2 MB (12.8) |
| 14400 requests from 16 clients, wall | 2.67 s | 0.66 s |

Latency per command in ms, p50 / p95. Single is one client; 16 is 16 processes issuing the same
command at once.

| command | Java single | lite single | Java 16 | lite 16 |
| --- | --- | --- | --- | --- |
| `ping` | 0.170 / 0.255 | 0.028 / 0.045 | 0.078 / 0.403 | 0.051 / 0.063 |
| `projects` | 0.647 / 0.929 | 0.073 / 0.143 | 1.333 / 2.192 | 0.943 / 2.359 |
| `programs` | 0.274 / 0.424 | 0.038 / 0.058 | 0.309 / 0.609 | 0.132 / 0.300 |
| `project` | 0.508 / 0.704 | 0.080 / 0.137 | 1.258 / 1.878 | 0.895 / 2.355 |
| `list` | 3.451 / 6.518 | 0.863 / 0.957 | 17.336 / 29.105 | 1.989 / 2.624 |
| `list` programsOnly, no metadata | 0.292 / 0.453 | 0.354 / 0.503 | 1.508 / 4.205 | 1.716 / 1.889 |
| `info` | 0.147 / 0.237 | 0.036 / 0.067 | 0.202 / 0.484 | 0.133 / 0.303 |
| `functions` | 0.178 / 0.262 | 0.035 / 0.052 | 0.183 / 0.446 | 0.068 / 0.080 |
| `functions` limit 5, contains | 0.185 / 0.277 | 0.036 / 0.066 | 0.204 / 0.425 | 0.068 / 0.083 |

What the numbers do and do not say:

* The large gains are start-up (about 19 times to the first `functions` answer), memory (about 50
  times at idle, about 90 times with 16 clients) and the `list` calls that read the project
  (4 times single, 9 times with 16 clients).
* On the cheap commands a request is dominated by the loopback round trip and the client; single
  client `hydra-lite` is 4 to 6 times faster at the median, with 16 clients it is only 1.5 to 2.7
  times faster and on `projects`, `project` and `list` without metadata the p95 is level with Java's
  (the one state lock is taken by all 16 threads). Nothing here is a claim about work the lite set
  does not do: no request in this table decompiles, edits or analyses.
* `list` without metadata is not faster than Java's (0.35 against 0.29 ms single): both read the
  index and stat the stored files; the Rust version does a little more per file.
* "Spawn to first answer" for the Python launcher includes the launcher itself (lock files, process
  creation by the task helper), which is why 95 ms is far above the 35 ms of a bare spawn.
