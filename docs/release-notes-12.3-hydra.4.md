# Hydra Engine 12.3-hydra.4: release notes (candidate text)

Status: prepared text, not a release. Nothing is pushed, tagged or published; the tag, the push and the
published body are the owner's. The published release body is built by the release workflow from the
`## 12.3-hydra.4` section of `CHANGELOG.md` (the `### Protocol 3 and the lock changes` part of `## Unreleased`
until the release renames the heading) plus its download table. This file is the longer record: the items the
release must state, the guarantees it may make and the test that decides each, and what was not run.

Rule for this file and for every document of the release (PROTOCOL-3.md D52, D58): a claim appears only with
the test that passed for it. Where the test has not been run, the row says so.

## 1. What a reader of the release must be told

- **`minClient` stays `1.0.0`** (D4). No existing client is rejected by a hydra.4 engine. It serves protocol 2
  and protocol 3 on one port. The one bump is reserved for the release that drops protocol 2.
- **Hydralysis 0.4.x refuses a hydra.4 engine by its own pin** (`hydra.py`, the pin check). That cannot be fixed
  on the engine side; it is stated here. Clients of hydra.2 and hydra.3 keep working at protocol 2.
- **Changes a protocol 2 client can see, by name (V1 to V11).** Every other behaviour is gated on protocol 3
  (G1 to G8 of PROTOCOL-3.md 5.1).

  | # | Change | Test that decides it |
  |---|---|---|
  | V1 | the upgrade gate refuses a writable upgrade of a canonical older-format project without a valid `backup` | `cc_e2` on the legacy fixture (`--legacy-project`) |
  | V2 | import wait fix: no ten-second `busy` after the front of the queue; one budget for an explicit `wait` | `cc_e3a` `import_wait`, `import_wait_explicit` |
  | V3 | bounded release of a dead client (`cleanupGraceS`, `abandonWaitS`) | `cc_e3b` `dead_client_lock_wait`, `owner_leave_bounded` |
  | V4 | a request for a program held by an abandoned request answers `busy` at once | `cc_e3b` `abandoned_holder` |
  | V5 | `cancel` and a `timeout` end a lock wait | `cc_e3b` `cancel_while_waiting` |
  | V6 | `protocolMin`, `protocolMax` in the endpoint file and the `ready` event | `cc_e1` (first test) |
  | V7 | the sidecar of every `fork_project` gains `purpose` and `disposable` | `cc_e2` `fork_sidecar` |
  | V8 | a sealed project refuses every writable path | `cc_e2` `sealed_refusal`, `candidate_then_seal` |
  | V9 | the work-conserving per-connection running cap, and the lane defaults | `cc_e3a` `v2_running_cap`, `v2_lane_defaults` |
  | V10 | the leave of a plain reader takes no exclusive lock | `cc_e3c` `reader_leave`, `reader_leave_all` |
  | V11 | concurrent forks to one destination give one success and `conflict` for the rest | `cc_e2a` `fork_race_conflict` |

- **Headless only.** There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by
  Ghidra 12.2 or 12.1.4.
- **A harness restart is needed once** after the Hydralysis catalog epoch (PROTOCOL-3.md 7.7).
- **State formats.** `CURRENT.log`, `MANIFEST.json`, `backup.json` and store v3 carry a `format` number. The
  reader that refuses a newer `format` with `format_unreadable` is **not in the code at the time of writing**
  (no `format_unreadable` in the engine sources), so the release text does not claim it. Add the sentence of
  PROTOCOL-3.md 5.2 only when the package that writes the refusal has landed and its test passes.
- **Build identity.** A local build says `<Ghidra version>-hydra.dev` and Hydralysis classifies it as stock
  Ghidra. The release workflow stamps `hydra.version` into `hydra.properties`; for a local build see the module
  README, "Stamping a local build". The workflow also checks that the stamp is inside the zip it built.

## 2. The guarantees hydra.4 may state (PROTOCOL-3.md 6.1)

Scope of every row: a process crash (`TerminateProcess`, a client kill), not a power loss or an OS crash. The
rows below are the ones marked "hydra.4" in 6.1; a row is stated in the published notes only when the line
"gate result" is filled in with a passing run. R1 did not run these gates (they need the finished integration
branch), so every gate result is open.

| # | Guarantee (6.1 wording, shortened) | Test that can fail | Gate result at preparation |
|---|---|---|---|
| GR1 | master, generations and uninvolved projects are not written; hydra.4 refuses every writable path of a sealed project (an accident guard, not a security boundary) | K1/K9 in every chaos iteration; `cc_e2` `sealed_refusal`, `candidate_then_seal`; `dt_e2` `seal_union` | not run by R1 (needs VF) |
| GR2 | corruption can touch only a disposable, unpublished artefact; a candidate generation is verified before it becomes head; a kill during a save does not leave an unopenable newest version | K2, K3, K6; 300 candidate-save kills; 400 save kills (200 NTFS, 200 ReFS); planted X1 | not run by R1; the ReFS half is skipped on this machine (no ReFS volume, `HYDRA_REFS_SCRATCH` unset), so it cannot be stated as passed here |
| GR6 | no client's request waits on a lock another client holds, outside the residual list of 3.9 | K13 and the reruns of B's `s1`, `s2`, `s4`, `s5`, `s7`, `s11`, `s13` | red-table rows BP4, BP5, BP6 were still red at the last landing report (8.8); not run by R1 |
| GR7 | a client crash never harms the daemon or other clients, and a dead client's queued write is never applied | K10; B `s4_dead` S4b; C scenario e | not run by R1 |
| GR8 | at the configured budgets the daemon answers `busy` instead of running out of memory | `-Xmx256m` / `-Xmx512m` runs, K14 | needs the governor package (E9), absent from the tree |
| GR9 | a native decompiler crash, hang or kill fails one request; a daemon kill leaves no orphan decompiler | the decompiler-kill lap, K7 | needs E9 and its SP3(b); absent |
| GR10 | a fork path is absent or complete, and no staging artefact survives the next sweep | K6; at least 300 kills during `fork_project` | not run by R1 |
| GR11 | a killed daemon is recoverable without manual repair, and operations in one project never change or delay another | K8, K9, K10; B's `s5`/`s13` | not run by R1 |

"A deaf script is killed" may be written only after the E7 items of 9.14 pass; E7 is absent from the tree.

## 3. What each passing test flips in the claims audit (8.3)

The coordinator flips a sentence when its row below has a passing run, and not before. R1 changed none of these
sentences (it made no document statement stronger).

| Claim | Flips when this test passes |
|---|---|
| C1 "writes never collide" | Hydralysis side: Y5 views, Y3 `before` checks, Z1 `SameAddressRace`; chaos gate 9.17 |
| C2 contained-script visibility | `dt_e4` `script_shared_visibility` (E4); Y4e |
| C3 "analysis never slows questions" | E3a lane defaults and caps (`cc_e3a` `v2_lane_defaults`), E3c `analyzing` (`dt_e3c`), gate 9.13 |
| C4 "different programs never wait on each other" | E3a maint lane and caps; E3c no wait inside a monitor and waiter caps; `s5`, `s13` |
| C5 "cleaned up at once" | `dt_e3b` `dead_client_lock_wait`, `owner_leave_bounded`; `dt_e3c` `reader_leave_no_freeze`; a non-cooperative script stays a limit until E7's gate |
| C6 queued import waits | `cc_e3a` `import_wait` |
| C7 `cancel` of a lock wait | `cc_e3b` `cancel_while_waiting` |
| C8, C9, C10 | no engine test (C9 is Z2, C10 is Z13) |
| C11 "three small fixes" becomes "five" | the E8 package: `NOTICE-HYDRA` was checked against the upstream commit and lists five modified core Java files and one added class; `dt_e8` is the test of the behaviour |
| U1 "any number of agents" | gate 9.17 (24 agents on 6 projects, 4 hours); until then "tested with up to 4 clients" |
| U2 starvation | `cc_e3a` `v2_running_cap` and 9.17 |
| U3 "serialized and never corrupt" | E8 and 9.15 and 9.17 |
| U4 replay from the store | Y1, Y2, 9.15 |
| U13 stale versions | `tests/test_bump_hydra.py` of Hydralysis (this package) shows the script edits the pin and the site constants; the claim flips when Y4a runs the script for the release and S2 commits the site edit |

## 4. Hello golden

The full protocol 3 hello of the release (PROTOCOL-3.md 9.3) is recorded by `examples/char_r1.py` on the
finished integration branch:

```
set HYDRA_RELEASE_GOLDEN=1
python Ghidra/Features/HeadlessSession/examples/characterization_tests.py --ghidra <install> --work <empty dir> ^
    --protocol 3 --require-v3 --only r1-hello --record
```

then review the diff of `examples/characterization/v3/r1-hello.json` as an addition, add its line to
`certification.manifest`, and commit it. The scenario fails (it never skips) when any capability, limit or policy
name declared in `Advertised.java` is absent from the engine's reply, and prints the absent names. It is
registered only when `HYDRA_RELEASE_GOLDEN=1`, so it cannot fail another package's run for want of a golden. On
the integration branch at the time of writing it reports the names of the packages that have not landed
(`health`, and the governor and script-worker names when declared).

## 5. Commands for the owner (not run by this stream)

```
python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder with the release files> --check     # Hydralysis
python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder> --write [--site-root <site repository>]
git tag v12.3-hydra.4 && git push origin v12.3-hydra.4        # publishes: the owner's action (OD5)
gh workflow run release.yml --ref <branch> -f version=12.3-hydra.4   # dry run: builds and tests, publishes nothing
```

Before the tag: rename `## Unreleased` of `CHANGELOG.md` to `## 12.3-hydra.4`, add the line that names the
upstream commit (``commit `<40-hex sha>` ``; the workflow fails without it), remove the
paragraph "Text prepared for the 12.3-hydra.4 section ..." and the "(not released)" suffix of the
`### Protocol 3 and the lock changes` and `### Storage integrity` headings (the release body would publish
them), and fill in section 2 above with the runs that passed.
