# Rust client for the Hydra Engine session protocol

`hydra-client` is a client of the protocol in
[README.md "Protocol (version 2)"](../README.md#protocol-version-2) and
[PROTOCOL-3.md](../PROTOCOL-3.md), speaking versions 2 and 3 over the daemon's loopback socket.
`hydra-agent` is the read/query agent host used to measure the multi-agent shape without CPython.

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
  "harness": "bench-rust",
  "maxChars": 10000000,
  "decompileTimeout": 120
}
```

Rows use the benchmark's schema (`agent`, `op`, `t`, `ok`, `ms`, and `key`/`sha` for the hashed
decompile and read replies), so the same aggregator reads Python and Rust agents.

## Measured (round 4, 2026-11-01)

Against the engine tree of this branch (`05015c8b73`; tested on the byte-identical
`o4-integration` install), 16 agents started together, 40 decompiles each, three interleaved
rounds per client on a shared machine (medians):

| per agent / tree | Python `ghidra_session.py` | this crate | delta |
|---|---|---|---|
| private peak MB | 13.90 | **2.71** | -80.5 % |
| CPU s | 0.144 | **0.037** | -74.3 % |
| agent wall s | 0.80 | 0.57 | -29 % |
| tree of 16 + daemon, peak MB | 697.7 | **531.1** | -166.6 MB (-23.9 %) |
| tree mean MB | 562.5 | 492.5 | -70.0 MB |

376 reply keys (decompiles and `BenchRead` outputs, the benchmark's projection and digest) are
identical in all six rounds, 0 differing. The differential harness also proves 34/34 replies
value- and byte-identical to the Python client's on the same requests, with the same deadline and
reconnect behaviour. The lane's report has the full evidence:
`D:/Projects/Hydra/_logs/rust-round4/rustclient/REPORT.md`.

