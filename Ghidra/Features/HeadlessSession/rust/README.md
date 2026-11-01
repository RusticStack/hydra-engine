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

## Measured (round 4, 2026-11-01)

**The full multi-agent benchmark** on `o4-integration2` (12.3-hydra.4): 16 agents (12 direct,
4 Hydralysis), 40 decompiles per direct agent, three rotated rounds per mode (Python direct
agents / Rust direct agents / 6+6 mixed), nine runs. **412/412 reply keys and one digest
(`285b55a2f873...`) in all nine runs**, the same digest the canonical all-Python bench produced.
Medians:

| metric | Python direct | Rust direct | mixed |
|---|---|---|---|
| workload wall s | 7.38 | **5.53** | 5.71 |
| tree CPU s | 30.87 | **22.83** | 25.90 |
| of which python processes s | 7.92 | 3.75 | 5.89 |
| of which rust agents s | - | 0.39 | 0.22 |
| ops/s | 111.79 | **149.19** | 144.48 |
| tree peak MB | 1139.1 | **937.4** | 1007.7 |
| tree mean MB | 793.5 | 766.9 | 807.6 |
| max python private MB | 324.1 | **150.2** | 206.1 |
| max rust private MB | - | 20.2 | 10.2 |

The 12 Python direct agents account for about 4.2 s of Python-process CPU (7.92 s with them,
3.75 s for the four Hydralysis agents and the eight subagents alone); the 12 Rust direct agents
use 0.39 s, 0.033 s each. The tree peak falls 201.7 MB and the Python side's private maximum
173.9 MB; the JVM is ~847-957 MB of the remaining tree, and this shape (Hydralysis publishes and
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

