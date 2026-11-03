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

# The front door (`hydra-front`): design, prototype and measurements

STATUS: PROTOTYPE, opt-in, not the default and not wired into `build-install.py`. It exists to answer
one question with numbers: how much of the daemon's idle cost can a Rust process absorb without
touching the protocol? The JVM daemon stays the default and is unchanged.

## What it is

`hydra-front` (crate `rust/crates/hydra-front`, 390 KB, standard library plus `serde_json` and
`windows-sys`) takes the place of the JVM in the launcher's start-up when `GHIDRA_SESSION_FRONT`
names it (`front_door_argv` in `ghidra_session.py`; unset, nothing changes). The launcher's own
command line (`java ... SessionMain -daemon -stateDir S -instance X ...`) is passed to it after `--`.

- It holds the instance lock `S/X.lock` (the launcher's liveness test), publishes `S/X.json` (same
  fields as the JVM's, its own pid, port and token) and listens on the loopback socket.
- It authenticates a client itself (`unauthorized` exactly as `Connection.authenticate`), negotiates
  the protocol with the engine's rule (`Client.requestedProtocol`) and answers `hello` and `ping`
  from a cached identity (`S/X.front-identity.json`: the last backend's protocol 3 `hello` result and
  endpoint file, keyed by a hash of the JVM command line) while no JVM is running. A cold `shutdown`
  is answered here too (with the engine's `conflict` when other clients are connected).
- Anything else starts the JVM (`-instance X.jvm`, so its endpoint file and lock do not collide) and
  **attaches** the client: a backend connection of its own, the client's first `hello` replayed to it
  (token swapped), and from then on every line goes through unchanged, both ways. One client is one
  backend connection, so per-connection state (protocol, label, programs, requests in flight, the
  ordered lane, lanes, `Governor` and `Waits` accounting, `queue`/`waited`, error model, progress
  events, cancel, ordering) is the JVM's own and exactly what a direct connection would have had.
  The front keeps no request state and parses nothing after the attach except to notice `shutdown`.
- `--backend-idle-s N` stops the JVM (protocol `shutdown`) when no client has been attached to it for
  N seconds; the next Ghidra-bound request starts it again. The JVM is in a kill-on-close Job Object
  owned by the front, so the launcher's `kill` of the front pid can never leave an orphan JVM.
- The backend is the authority for everything about programs, projects, locks, scripts, the decompiler
  and the trace *writer lease*. The front never reads or writes a project or program.

## What is NOT achievable (and why)

- Anything that touches Ghidra program or project state stays in the JVM: `open_project`,
  `open_program`, `info`, `functions`, `decompile`, `list`, `edit`, `script`, `fork_project`, `status`,
  `programs`, `projects`, `health`, imports, saves. That is nearly the whole protocol; the front only
  decides *when* the JVM exists.
- `status` and `health` are not answered natively: their results are the JVM's scheduler, governor,
  lanes, memory, clients and projects. A launcher `health` or any monitor that polls `status` starts
  the JVM, which removes the saving. (A cold `status` could be synthesised for an empty daemon, but
  it would be a second implementation of `Session.info`/`Scheduler.describe` that must track every
  engine change; not done.)
- Trace commands are NOT served natively in this prototype. The Rust trace `Service` could answer
  `trace_query/explain/diff/check/info/list` from the committed snapshots without the JVM, but the
  JVM adds the writer lease (`TraceLeases`), the symbol table of the open program, the disk reserve
  and the lane choice, and two processes reading and one writing the same store has not been proven
  safe here. Until it is, a trace-heavy workload keeps the JVM up and the front is a 30-60 us pipe.
- `hello`/`pid`: the front's `hello` carries the front's `pid` and `listen` (patched), the JVM's
  `status`/`health` carry the JVM's. A client that compares them sees two pids.
- Instance names differ: the JVM runs as `X.jvm`, so `paths.instance`/`endpointFile` in a *forwarded*
  `status` name the backend; the front patches them only in the `hello` it answers or forwards.
- The client id in a cold `hello` is the front's counter, not the JVM's; once attached, ids are the
  JVM's. Ids are labels, not keys, in the protocol, but a golden that pins them would see it.
- `shutdown` from an attached client is judged by the JVM against the clients *attached to it*; a
  detached client is invisible to that check.
- No Linux/macOS: the Job Object and the lock rely on Windows (the code compiles elsewhere with the
  Job Object as a no-op, untested).

## Measurements

One machine (24 logical CPUs, shared with other lanes running at the same time, so single numbers
are noisy; medians of the listed runs). Logs: `E:\Projects\Hydra\_logs\h7ront`. The JVM is the
final2b (h6) install; the front install is the same files plus `hydra-front.exe` and the launcher hook.

### Idle cost of an empty daemon (30 s window, nothing connected but one `hello`)

| | working set | private | threads | CPU in 30 s |
|---|---|---|---|---|
| JVM daemon (today) | 179 MB | 244 MB | 49 | 0.000 s |
| front, JVM not started | **5.1 MB** | **0.9 MB** | 2 | 0.000 s |
| front + attached JVM | 5.5 MB + 191 MB | 1.0 MB + 258 MB | 2 + 68 | n/a |

The saving is real but it is only the *empty* daemon: a JVM that has served a decompile holds
hundreds of MB, and the front cannot give that back while a client is attached to it (the JVM
holds that client's programs). `--backend-idle-s` stops the JVM only when no client is attached.

### Start-up

| | time |
|---|---|
| `ensure` of the JVM daemon (class cache hit) | 5.1 s (one sample; the JVM reports ready in 0.6-1.4 s) |
| `ensure` of the front from the cached identity | **0.76 s** |
| first Ghidra-bound request through a cold front (JVM start + replayed hello) | 1.1-1.7 s |
| same after a `--backend-idle-s` stop | 0.5-4.7 s (loaded machine) |
| native `hello` of a cold front | 10-11 ms |

### Per-request cost of the hop (one connection, loopback, median of two runs of 5000)

| request | JVM direct | via front (attached) | native in the front (cold) |
|---|---|---|---|
| `ping` | 54-67 us | 92-126 us | **32 us** |
| `projects` (75 B) | 76-92 us | 131-160 us | n/a |
| `status` (4.5 KB) | 321-370 us | 334-415 us | n/a |

The hop costs **30-60 us** per request (two extra loopback sends and a thread hand-off), noise-level
next to any request that does Ghidra work (a decompile is 5-500 ms).

### 16-agent bench (`multiagent_bench.py`, 412 keys), front vs direct, same install files

| | n | tree CPU (median) | JVM CPU | peak MB | digest | waits |
|---|---|---|---|---|---|---|
| direct | 4 | 22.3 s | 17.3 s | 1041 | 285b55a2f873abb9 | 0 |
| front | 4 | 22.4 s | 16.5 s | 1048 | 285b55a2f873abb9 | 0 |
| direct, 4 trace readers + live capture | 3 | 27.5 s | 20.1 s | 1132 | 285b55a2f873abb9 | 0 |
| front, 4 trace readers + live capture | 3 | 28.3 s | 20.2 s | 1173 | 285b55a2f873abb9 | 0 |

(An earlier set of six pairs: 24.4 s direct vs 25.2 s front.) The front adds no measurable CPU or
memory to a busy daemon; with trace readers the tree is about 3% higher, inside the run-to-run
spread (direct 27.3-27.5 s, front 27.2-30.6 s). One of six early direct runs failed its digest with
39 `busy` errors: a flake of the JVM path itself, not of the front. The trace-reader runs have
`not_found` errors on the live capture's first reads in both modes (a start-up race of the harness).
Trace-reader tree CPU "vs h6" is therefore **the same as h6 plus the hop**: the front does not
reduce it, because trace commands are not served natively (see above).

## Gates (final binary; the suites start every daemon through the launcher with `GHIDRA_SESSION_FRONT` set)

Two modes: **default** (no cached identity: the front starts the JVM at once to learn it, so every
client attaches at `hello`) and **lazy** (`GHIDRA_SESSION_FRONT_OPTS=--lazy`: the JVM is stopped
after learning, so each suite daemon starts cold, answers `hello` itself and starts the JVM at the
first Ghidra-bound request, which exercises the late attach and `attach_all`).

| gate | default | lazy |
|---|---|---|
| `contract_tests.py` | 7/7 | 7/7 |
| `client_compat_tests.py --exe choice.exe --dll version.dll --legacy-project` | 61/61 | 61/61 |
| `session_smoke.py` | pass | pass |
| golden 9.1 (`run_golden.py default`, both paths, fixtures + raw) | PASS | PASS |
| trace daemon cases (`trace_agent_workload`, `trace_client_identity`) | 2/2 | 2/2 |
| 16-agent bench: 412 keys, digest 285b55a2f873abb9, 0 waits | yes (4 of 4 pairs) | n/a |
| `front_compat.py` (differential vectors, front vs JVM, cold and warm) | 59 vectors agree | - |

What the lazy run found, and fixed: the JVM's `status.clients` and its `shutdown` check count only
the clients attached to it, so a client served natively and idle was invisible
(`contract_tests.py hello`); a client attached twice by two threads (a leaked backend connection
that made a later `shutdown` answer `conflict`, `cc fork_race_rk`). The front now attaches every
connected client when the JVM starts and holds a client's link for the whole attach.

Not run: the K1-K17 kill matrix, the soak and `characterization_tests.py`; `gradlew :HeadlessSession:ip`
cannot run offline here (no flatRepo), so the IP headers were applied by hand to every new file.
`test_launcher_lean.py` has one failure (`JitOneShot.test_default_on`) that is identical on main.

## Recommendation for h7

**Merge as an opt-in, documented prototype (off by default, not packaged, not in `build-install.py`);
do not make it the default and do not count it as an h7 deliverable.**

- For: every gate passes in both modes, the differential test finds no reply difference except live
  values, the hop is 30-60 us, a busy daemon costs the same, and an idle daemon drops from ~180-240 MB
  to 5 MB while the JVM sleeps. The change to shipped code is one function in the launcher that does
  nothing unless an environment variable names an existing file.
- Against making it default: the saving applies only to a daemon that nobody has asked for Ghidra
  work yet, or (with `--backend-idle-s`) after every client that used Ghidra has left. Agents that
  keep a project open keep the JVM; `status`/`health` polling starts it. The JVM start moves to the
  first real request (1.1-1.7 s) and the warm caches die with every idle stop. The reply differences
  listed above (two pids, instance names in a forwarded `status`) are small but real for a client
  that compares them. Trace-heavy work, the original motivation, is not helped until the trace service
  is served natively, which needs a proven single-writer/many-reader store protocol across two
  processes and the lease and symbol-table logic moved or duplicated. That is the next step if h7
  wants the value; it is a separate, larger lane.
- Not covered by evidence: the kill matrix (K1-K17), soak, characterization suites, non-Windows.
