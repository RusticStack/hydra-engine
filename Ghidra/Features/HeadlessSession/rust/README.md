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

# Rust client for the Hydra Engine session protocol

`hydra-client` is a client of the protocol in
[README.md "Protocol (version 2)"](../README.md#protocol-version-2) and
[PROTOCOL-3.md](../PROTOCOL-3.md), speaking versions 2 and 3 over the daemon's loopback socket.
`hydra-agent` is the direct-agent host used to measure the multi-agent shape without CPython: the
benchmark's read/query work **and** its overlay and fork writes.

The shipped Python client (`support/ghidra_session.py`) remains the default. This crate exists
because the 16-agent benchmark's Python peak is about 20 client processes at 18-21 MB each
(CPython's floor is 8.5 MB); a Rust agent is 2-4 MB with no interpreter start-up. Behaviour is
proven reply-identical by the lane's differential harness and the benchmark's reply digests;
[PORTING.md](PORTING.md) maps every ported behaviour and lists the deliberate differences.

## Build and test

```bash
cd Ghidra/Features/HeadlessSession/rust
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Rust 1.99, edition 2024, Windows first. The only dependency is `serde_json`; no `unsafe`.

## Run

```bash
# one read/query agent against a running daemon (the spec shape multiagent_bench.py writes)
hydra-agent agent --spec agent-00.json

# the differential harness's Rust side: one request per stdin line, one engine answer line back
hydra-agent call --endpoint <state>/<instance>.json --keep-raw

# identity, ping and a status summary
hydra-agent probe --endpoint <state>/<instance>.json
```

An agent spec:

```json
{
  "name": "agent-00",
  "endpoint": "C:/state/rusticre.json",
  "rows": "rows/agent-00.jsonl",
  "project": {"name": "kotor", "gpr": "C:/work/kotor.gpr", "program": "/swkotor.exe"},
  "hot": ["0x401000", "0x402000"],
  "fresh": ["0x403000", "0x404000"],
  "reads": ["0x401000", "0x402000", "0x403000", "0x404000"],
  "edit": "0x401000",
  "edit_sig": "void Foo::bar(int)",
  "edit_name": "Foo::bar",
  "fork": true,
  "fork_dir": "C:/work/forks/agent-00",
  "plan": [
    {"op": "decompile_hot", "arg": "0x401000"},
    {"op": "read_script", "arg": ["0x401000", "0x402000", "0x403000", "0x404000"]},
    {"op": "info"}
  ],
  "harness": "bench-rust",
  "maxChars": 10000000,
  "decompileTimeout": 120
}
```

Rows use the benchmark's schema (`agent`, `op`, `t`, `ok`, `ms`, and `key`/`sha` for the hashed
decompile and read replies), so the same aggregator reads Python and Rust agents. `edit`, `fork`
and `fork_dir` add the benchmark's overlay and fork rounds; `plan`, when present, is the order
the driver chose for the read/query work (the Python agent shuffles it with its seed, and the
driver can hand the same order to both clients).

## Packaging

`build-install.py` builds the release binary and writes it with a provenance marker:

```bash
python -I build-install.py                      # -> Ghidra/Features/HeadlessSession/build/rust/support/
python -I build-install.py --install <install>  # also into <install>/Ghidra/Features/HeadlessSession/support/
python -I build-install.py --check --install <install>   # verify an installed copy against its marker
```

The build is `cargo build --release --locked` with `CARGO_INCREMENTAL=0` and a target directory
under `build/` (the source tree stays clean for `:HeadlessSession:ip`); `rust/.cargo/config.toml`
passes `/Brepro`, so two builds of the same tree produce the same SHA-256 (489472 bytes,
`dc06e22e...`). The marker (`hydra-agent.provenance.json`) records the crate and client versions,
the protocol, the commit, the cargo/rustc versions, the size and the SHA-256.

Every `.rs` file carries the project's Apache-2.0 block header, and every `.toml`/`.md` file the
`#` form (`README.md`/`PORTING.md` inside an HTML comment); `gradle/support/ip.gradle` treats
`.rs` as a C-style source and `.toml`/`.md` as `#`-comment sources, so the `ip` task checks the
headers. `certification.manifest` lists only the two non-source files (`Cargo.lock`,
`.gitignore`).

`build.gradle` registers `rustClient`, which runs this script for `assembleDistribution` (the
full and headless installs). A machine without cargo gets a clear message and the engine build
continues; with cargo, a failure to compile the client fails the distribution build. `gradle
build`, the tests and `:HeadlessSession:ip` never build it. The Python client remains the default
and is unchanged.

## Measured (round 4, 2026-11-01)

**The full multi-agent benchmark** on `o4-integration2` (12.3-hydra.4): 16 agents (12 direct,
4 Hydralysis), 40 decompiles per direct agent, three rotated rounds per mode (Python direct
agents / Rust direct agents / 6+6 mixed), nine runs. **412/412 reply keys and one digest
(`285b55a2f873...`) in all nine runs**, the same digest the canonical all-Python bench produced.
Medians:

| metric | Python direct | Rust direct | mixed |
|---|---|---|---|
| workload wall s | 5.56 | **5.53** | 5.61 |
| tree CPU s | 27.55 | **22.34** | 22.07 |
| of which python processes s | 6.34 | **3.91** | 4.91 |
| of which rust agents s | - | **0.39** | 0.12 |
| ops/s | 147.84 | **148.64** | 147.06 |
| tree peak MB | 1123.3 | **969.4** | 993.1 |
| tree mean MB | 787.7 | 766.9 | 747.1 |
| max python private MB | 326.6 | **149.9** | 206.4 |
| max rust private MB | - | 19.9 | 9.7 |

The 12 Python direct agents account for about 2.4 s of Python-process CPU (6.34 s with them,
3.91 s for the four Hydralysis agents and the eight subagents alone); the 12 Rust direct agents
use 0.39 s, 0.033 s each. The client's private maximum falls 176.7 MB and the tree peak
153.9 MB; the JVM is 751-845 MB of the remaining tree, and this shape (Hydralysis publishes and
six forks) is not the read/query shape the owner's 549 MB target was measured on.

The read/query shape of round 3, on the same engine bytes, measured per agent and tree:

| per agent / tree | Python `ghidra_session.py` | this crate | delta |
|---|---|---|---|
| private peak MB | 13.90 | **2.71** | -80.5 % |
| CPU s | 0.144 | **0.037** | -74.3 % |
| agent wall s | 0.80 | 0.57 | -29 % |
| tree of 16 + daemon, peak MB | 697.7 | **531.1** | -166.6 MB (-23.9 %) |
| tree mean MB | 562.5 | 492.5 | -70.0 MB |

376 reply keys (decompiles and `BenchRead` outputs, the benchmark's projection and digest) were
identical in all six read-shape rounds, 0 differing. The differential harness also proves 34/34
read replies value- and byte-identical to the Python client's on the same requests, with the same
deadline and reconnect behaviour. The lane's reports have the full evidence:
`D:/Projects/Hydra/_logs/rust-round4/rustclient/REPORT.md` and
`D:/Projects/Hydra/_logs/rust-round4/rustclient2/REPORT.md`.

