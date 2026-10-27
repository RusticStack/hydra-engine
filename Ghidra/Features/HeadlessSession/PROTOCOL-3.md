# Hydra Engine protocol 3: the engine contract, the Hydralysis obligations and the work plan

Status: **design, not implemented.** Nothing in this file describes shipped behaviour. The text
fixes one design for the eight problem areas the investigation raised (durable annotations,
concurrency, lanes and admission, script isolation, upgrade and backup, supervision, platform and
fork maintenance, import/export/golden gating) and orders the work to build it. How the session
works today is in [README.md](README.md) ("Protocol (version 2)") and
[ARCHITECTURE.md](ARCHITECTURE.md).

Evidence conventions. Every `File.java:line` below was read on branch `feat/session-extract`
(commit `b6df709e1e`, the tree this file is committed on); every `file.py:line` was read on
Hydralysis branch `feat/hydralysis-0.5` (commit `d0466bc`, package `src/hydralysis`, formerly
RusticRE). Anything not marked that way is a proposal. A number marked *unmeasured* has no
measurement behind it on this machine: it is a starting value to be replaced by the measurements in
[Release gates](#9-release-gates). Appendix A lists the code facts the design depends on and where
each was read; Appendix B lists what the three designs it was synthesised from got wrong or left
out, as found by reading the code.

## Contents

1. [What is decided](#1-what-is-decided)
2. [Conflicts resolved, one by one](#2-conflicts-resolved-one-by-one)
3. [The engine contract](#3-the-engine-contract)
4. [The Hydralysis state contract: the op-log, generations, backups, commit](#4-the-hydralysis-state-contract)
5. [Compatibility with hydra.2/3 clients and engines](#5-compatibility-and-the-release-train)
6. [Honest limits](#6-honest-limits)
7. [Client obligations (Hydralysis)](#7-client-obligations-hydralysis)
8. [Work packages](#8-work-packages)
9. [Release gates](#9-release-gates)
10. [Open owner decisions](#10-open-owner-decisions)
11. [Appendix A: code facts and where they were read](#appendix-a-code-facts-and-where-they-were-read)
12. [Appendix B: corrections to the source designs](#appendix-b-what-the-source-designs-got-wrong-or-left-out)

---

## 1. What is decided

The engine adds **facts and gates**; Hydralysis keeps the **record**.

- **One persistent op-log, and it is the Hydralysis overlay store** (store v3, written with
  fsync, sealed, with a previous-generation fallback). It is at the same time the journal, the
  crash-recovery record and the commit source. The engine's `Journal` and `Overlay` stay in
  memory and are documented as non-durable conveniences for direct clients. No engine-owned
  write-ahead log, view store, lineage or `view_*` command family is built in this train
  (reasons and the re-open criteria: D5).
- **Commit publishes a new generation, never a modified master.** Fork the current generation
  (`fork_project purpose:"generation"`), replay the records with `before` checks inside one
  transaction, verify, force every file to disk, then append one CRC'd record to an append-only
  `CURRENT.log`. That append is the single commit point. No directory is renamed, so Windows
  open handles, Defender and indexers cannot break a publish. Generation 0 (the adopted project)
  is never written. In-place replace and automatic deletion are not part of this train.
- **Backup is a fork** (`fork_project purpose:"backup"`) with one manifest schema, one
  implementation class (`ProjectBackup`), and a self-hash. Restore is a fork from the backup to a
  new path. There is no `restore_project` and no `replace_project`.
- **The upgrade gate** refuses `open_program writable upgrade:true` on anything not provably
  disposable unless a verified backup of that project's current revision is named.
- **Admission, isolation and supervision** are extensions of the existing seams (`Scheduler`,
  `Connection`, `Caller`, `ScriptCommands`, `Session.info`), plus one new inline command,
  `health`. There is no new admission class, no command table, no Java fault-injection layer.
- **Protocol 3 is a negotiated contract level.** The engine serves protocols 2 and 3 on one
  port. A connection that does not ask for 3 sees byte-identical replies, which is checked by the
  existing 317-request characterization goldens. Everything else about 3 is additive.
- **Ordering.** Hydralysis durability and commit ship first, on hydra.2/3, with no engine change.
  The engine work follows in small packages that each pass the characterization diff. Per-agent
  default views, in-place replace and helper-JVM script isolation are explicitly later or out.

## 2. Conflicts resolved, one by one

Each row: what collided in the source designs or in the judges' verdicts, what is decided, and why.
"Source" means the three synthesised designs (A: minimal additive; B: robustness first; C: agent
ergonomics) and the investigation's critic.

| # | Conflict | Decision | Why |
|---|---|---|---|
| D1 | Five analyses each wanted a `hydra.3`/protocol-3/`minClient` bump with different content; the upstream merge is also called hydra.3 | **hydra.3 is the upstream merge only** (no protocol change). **hydra.4 is protocol 3**, one tag. The engine packages merge separately to one integration branch and are gated one by one; the Hydralysis pin moves once. | The merge was golden-gated on its own (KotOR 8616/8616 identical to hydra-2; report in `_golden/baselines/hydra-3-candidate`). Mixing protocol work into it would make a decompile difference unattributable. |
| D2 | `README.md:986-990` says additions need no protocol change; all three designs still bump to 3 | The bump is kept as a **negotiated contract level**, not a break. `hello` echoes the `protocol` the client sends (the hydra.2 client already sends `protocol=2`, `ghidra_session.py:850-852`), within `[2,3]`; absent means 2. Reply keys that only a v3 client can use are produced only for a v3 connection, at the bounded list of sites in 3.1. | A v2 connection then stays byte-identical, so the seven existing scenarios (317 requests) remain an exact regression suite for a Java code base with no unit tests. The cost is about eight conditionals, listed. The alternative (always additive, re-record goldens under a "superset of old keys" check) is wire-compatible and is the fallback if the site list grows past about twelve; it changes no wire rule. |
| D3 | Endpoint file and `ready` event: protocol 3 only (A), or the lowest served plus a maximum (C) | Endpoint file and `ready` carry `"protocol": 2` (the lowest served), plus `protocolMin: 2`, `protocolMax: 3`. | The stock client refuses the endpoint on inequality (`ghidra_session.py:1000`) and the `hello` on inequality (`:113`). A hydra.4 client library accepts any overlap of `[2,3]` with the daemon's range and uses the highest. So: a hydra.2/3 stock client works against a hydra.4 daemon at protocol 2; a hydra.4 client works against a hydra.2/3 daemon at protocol 2. |
| D4 | `minClient` bump now (B asked), or never | `minClient` stays `1.0.0`. The new client library is `CLIENT_VERSION 1.1.0` (something added). The one bump is reserved for the release that drops protocol 2. | Nothing is non-additive for a client that does not opt in. A bump would reject every existing client for no safety gain. |
| D5 | Persistent op-log: engine WAL/ViewStore (B, C) versus the Hydralysis store (A) | **The Hydralysis store.** No engine-owned op-log in this train. Re-open only if (a) a non-Hydralysis client needs durable engine annotations, or (b) a spike shows bulk ops (`import_types`, `import_archive`, struct) replay on a changeable view program with the same result as the fork-based working copy. | Hydralysis never uses the engine edit path: it forks, then replays RusticQuery `apply_overlays` (`workcopy.py:352-405`, `RusticQuery.java:2305-2345`). The five native engine ops cover rename, label, comment, signature and data_type only; struct, variable, function_create/body/delete and the two bulk imports exist only as RusticQuery code. An engine log would need a second Java implementation of all of them, the biggest risk any design carried. The store already has atomic writes, a monotone revision, per-edit `by`/`at`, a subject journal, and mandatory `expect_revision` with subject-aware rebase (`revisions.py`). What it lacks is hardening (D14), `before` values, a master binding and a commit path, which this design adds. |
| D6 | Three on-disk formats for "journal" (`<project>.journal`, view op-log, `recovery/*.ops.json`) | None of the three. Journal = recovery = commit source = the store v3 record set. An optional dump of an orphaned engine journal to `<stateDir>/recovery/` (E3b, default off) exists only for direct clients. | One format means one reader and one recovery rule. |
| D7 | Two subject/conflict models (store revision plus `before` drift; seq plus subject rebase) | **One subject record** `{subject, field, before, after, seq, by, at}` inside each edit's `effects[]` (4.2). Conflict decisions use the **coarse subject** (the strings of `revisions.subjects_of`, unchanged); `field` only refines drift checks and the probe. | Existing rebase tests stay valid; a rename and a comment at one address still count as one subject for conflicts but are two effects for drift. |
| D8 | Two backup components with different manifests | One: `fork_project purpose:"backup"` implemented in a new `ProjectBackup` class (not inside `ForkCommands`, 278 lines today). One manifest schema with a `writer` field (`engine` or `hydralysis`), so the Python-written manifest used on hydra.2/3 and the engine-written one are the same format. | The commit works before the engine change (H2 in design A) and later switches writer without a format change. |
| D9 | Commit mechanism: fork+replay+publish, promote a fork's DB into `.rep`, or apply and save in place | Fork+replay+verify+publish as a **new generation**. No Ghidra-internals write, no promote, no in-place save of a canonical project. | Nothing in the commit path can corrupt the master; the one-way format step lands on the new generation only. |
| D10 | Commit point: atomic replace of `targets.json` (A), pointer record in an append log (B), `lineage.json` replace (C) | **Append one CRC'd line to `CURRENT.log` and fsync.** `targets.json` is only a cache of it. | Replace-based pointers have no integrity check and no recovery rule; an append log with per-line CRC and a "last valid line wins, a torn tail is ignored, a mid-log gap is loud" rule does. |
| D11 | **New finding, in none of the three designs:** `target["key"]` is `sha256(resolved gpr + program)` (`targets.py:114-117`) and keys the overlay store (`workcopy.py:46-47`), the working directory (`:105-106`), the view re-key (`:36-43`), the export header (`exporting.py:118`) and `stop()` (`query.py:224`). A pointer flip that changes `gpr` would orphan every store. | The target keeps a **stable `key` for life**: at lineage creation the existing key is stored in the record (`lineage.origin_key`) and `resolve()` returns it; only `gpr` follows `CURRENT.log`. `stop()` releases the programs of every generation of the lineage. | Without this, the first commit silently abandons the analyst's overlay store. |
| D12 | "Canonical" for the upgrade gate: no sidecar (A, C) or not provably disposable (B) | **Disposable only if** the project has a fork sidecar with `disposable:true` and is not a published generation. A sidecar without the field (written by hydra.2/3) counts as disposable only when `kind` is `ghidra-session-fork`. `fork_project` writes `disposable:true` by default and `false` for `purpose:"generation"`. No sidecar, or any doubt: canonical. | Generations are made by `fork_project`, so "no sidecar" would exempt every generation from the second one on. |
| D13 | Backup freshness test | The gate checks `backup.source.revision == Revision.of(project)` **and** the manifest self-hash **and** every file's size. Integrity of content is the manifest's per-file SHA-256, re-verified by the client before it relies on a backup. | `Revision.of` identifies the large database files only by size and mtime (`Revision.java:51-80`, files above `HASH_LIMIT` = 1 MiB are not hashed): it proves "this is the same saved state", not "the bytes are intact". The engine gate is a guard against accidents, not a security boundary against a local process with the same rights. |
| D14 | Durable IO: skipped (A: "proven"), engine-side CRC/WAL (B), not mentioned (C) | **First thing shipped, on hydra.2/3, no engine change:** `durable.py` (fsync before replace, write-through replace on Windows, retry on `PermissionError`, sealed JSON with a previous-version fallback, never "start empty"). | `_save_store` (`workcopy.py:72-80`) and `write_json` (`backends.py:50-54`) do `write_bytes` then `replace` with no fsync: a power cut can leave a zero-length or stale store, which is the only record on hydra.2/3. 52 other write sites go through the same two chokepoints or `write_text`. |
| D15 | Idempotency: `rk`/`opId` everywhere (B, C) versus none (A) | Two parts. (1) The client **stops blindly retrying non-idempotent engine calls** after `closed` (`hydra.py:268-287` retries every command once), and reconciles through the program's `overlay_state` marker instead. (2) Engine mutating edit commands (`edit`, `rename`, `comment`, `apply_overlay`) accept an optional `rk` and answer a repeat with `replayed:true`. Commit and backup jobs are idempotent by their own id and intent log. | The marker already makes `apply_overlays` recoverable; the blind retry is the real hole. `rk` costs little where `expect` is being added anyway. |
| D16 | Lanes: where `save` goes; explicit hint versus inference | New **MAINT** lane for `fork_project`, `refresh`, `reopen`, `promote_overlay` and `save`. `script` is `quick` **only with an explicit `lane:"quick"` and a `timeout` of at most `quickScriptMaxS`**; no inference from the timeout or from the script's directory. | RusticRE 0.4.x already sends `timeout_s+5` (`query.py:91`) but pins hydra.2 and refuses hydra.4, so inference would help no one it could reach; and silent lane changes for unknown clients are not worth a hidden behaviour. (Judges disagreed; this is the safer reading.) |
| D17 | Replace `Scheduler`/`ImportGate` with an `AdmissionController` (B, C), or extend | **Extend.** Fair key, caps, queue info, MAINT lane and the import wait fix are changes inside `Scheduler` and `ImportCommands`. | `laneOf(String)` is static and cmd-only (`Scheduler.java:59-69`), so it gains a request argument; that is the only signature change. |
| D18 | Validate before queueing (C) | **Validate-before-wait:** the request-shape checks run only when the request would otherwise have to wait for a slot. | A request that is admitted at once keeps today's order of errors, so no existing golden changes; a request that would sit in a queue for a minute and then fail `bad_request` fails at once instead. |
| D19 | Dead-client release | One design, owned by E3b: bounded wait, interrupt, then release regardless, **including the 600 s waits in `leaveProject`/`releaseUse`** (found in the code, in none of the designs): `Session.disconnect` passes `CLEANUP_WAIT_MS` (600 000 ms, `Session.java:52,121`) to `leaveProject`, which takes the project lock and the program's exclusive lock with that wait (`ProjectCommands.java:286-322`, `ProgramCommands.java:480-520`). A stuck holder therefore blocks `disconnect` for 10 minutes per program even if `Connection.run` stops waiting. | A bounded `awaitTermination` alone would not release anything. |
| D20 | Script isolation: exclusive by default (import-export item), private instance, or trust by directory (C) | Per-request `isolation: shared|private|exclusive`, default `shared` (today). RusticQuery stays `shared`. User `ghidra_run` uses `private` **only when the working copy has nothing unsaved**, else `exclusive`. RusticQuery is pinned by an optional `scriptSha256`. No trust by directory. | `private` reads the **stored** file (`getReadOnlyDomainObject`), so it cannot see unsaved shared edits. Hydralysis working copies hold their edits unsaved in the daemon until a saver runs (`workcopy.py:352-359`), so a private run on an edited view would silently answer from the master. Found in the code, in none of the designs. |
| D21 | Wedge detection and registry | `health` inline from a watchdog snapshot; wedge decided by the client after three probes. The daemon registry is launcher-side Python; an entry is live iff the instance lock is held (`Daemon.jvm_alive`, `ghidra_session.py:969-979`). | Pid reuse cannot fool a held OS lock. No Java registry class. |
| D22 | Fault injection compiled into the engine (B, C) | **No Java fault layer.** Engine tests kill and suspend processes from outside. One test hook is allowed: a launch property `-Dghidra.session.testHooks=true` registering `debug_stall`, advertised in `hello.platform.testHooks` and turning `health.state` to `degraded`. Hydralysis commit fault points are Python (`durable.fault(name)`, a no-op unless `HYDRALYSIS_TEST_FAULT` is set). | A `Runtime.halt` in a release binary is a hazard larger than the bug it finds. |
| D23 | Doctor in five places | One module (`doctor.py`), read-only, never starts a JVM. The engine supplies `hello.paths/platform/analysisIdentity`, `format`, `health`. | |
| D24 | Ergonomics scope (C) against the correctness spec | Adopted because each is tied to a verified defect: error `next`/`retryAfterMs`, validate-before-wait, queue info, `applied` on cancel, widened `EngineError` (`hydra.py:61-63` drops `holderInfo`, `heldMs`, queue), a fast/engine tool pool split (`mcp.py:22-23`: four workers, eight outstanding). **Not adopted:** call detach/patience as a new state next to jobs (a bounded wait that returns the engine's structured `busy` achieves "never block long" without it), reply diet, a catalog-hash freeze beyond the one epoch in Y0d. | |
| D25 | 20 tools | A target, not a cap. Nothing here needs a 21st tool. One catalog epoch (Y0d) adds `backend.action` values `doctor` and `backups` and an `options` bag to `backend`, `ghidra_run`, `job`; every other feature rides existing `options` bags (`type_edit` kinds, `status` `show`). Section 7.7. | Running sessions cache tool lists (`mcp.py:45`, `listChanged: False`): schema changes must happen once. |
| D26 | Per-agent default views | Not in this train. `shared` stays the default. Precondition list in Y5. | Needs publish/merge to have soaked, a stable agent id (`rusticre:<pid>` today) and a measured named-view cost (the 1.4 s figure is a single unreproduced run). |
| D27 | In-place replace / restore-replace | Not built. If ever: its own capability, own fault matrix on the owner's volumes, owner decision. | Directory renames over open handles are the Windows failure the generation design avoids. |
| D28 | Retention | **No automatic deletion** of backups, generations or candidates in this train. Unfinished candidates are invisible (no valid manifest) and listed by `backend action=backups` for manual removal. | Every automatic delete is a data-loss surface; the disk cost of keeping is bounded by the 50 GB ask-first rule. |
| D29 | Baseline ordering | Golden baselines are captured on the released hydra.3 install from COW or full **copies** with tree hashes before and after, before any engine package merges (the hydra-3-candidate captures already exist). | The three comparisons (12.1.4 vs hydra.2, hydra.2 vs hydra.3, after-commit vs working copy) are never mixed in one diff. |
| D30 | Test-file collisions | `daemon_tests.py` and `characterization_tests.py` get an extension loader in E0 (`examples/dt_*.py`, `examples/char_*.py`), so every later package adds its tests in its own file. | Lets packages in one wave touch disjoint files. |

## 3. The engine contract

All of this is the target for hydra.4. "v3" means a connection whose `hello` asked for `protocol:3`.

### 3.1 Negotiation, gating and capabilities

**Request.** The client library already sends the field:

```json
{"id":1,"cmd":"hello","token":"<endpoint token>","client":"hydralysis","harness":"claude-code","clientVersion":"1.1.0","protocol":3}
```

**Rule.** `reply.protocol` = the requested value when it is in `[2,3]`; 3 when it is larger;
2 when absent or smaller. The connection records it (`Client.protocol`, helper `Client.v3()`).
A client library that cannot speak `reply.protocol` raises `IncompatibleError` naming both
sides, as today.

**Endpoint file and `ready` event** (`HeadlessSession.java:187`, `:356`):

```json
{"protocol":2,"protocolMin":2,"protocolMax":3,"minClient":"1.0.0","hydraVersion":"12.3-hydra.4", "...":"..."}
```

`protocol` means "the contract a client that knows nothing newer can use". It is deliberately
the lowest served; the honest statement is `protocolMin`/`protocolMax`.

**Where v3 gating applies (the complete list; everything else is byte-identical for v2):**

| Site | v3-only content |
|---|---|
| `Session.info(c)` (hello and the `status` header) | `protocolMin`, `protocolMax`, `capabilities`, `limits`, `policy`, `paths`, `platform`, `analysisIdentity` |
| `Scheduler.describe(boolean v3)` (`status.scheduler`) | `maint` lane, `waiting[].position`, `waiting[].estimatedWaitMs`, `oldestWaitMs`, `longestRunningMs`, `starving`, `perKeyCap` |
| `status.programs[]` | `abandonedRequests[]` |
| `ProjectCommands.openProject`, `project`, `info` | `format` |
| `ForkCommands.forkProject` success | `cost`, `warnings`, `purpose`, `manifest` (backup) |
| `ScriptCommands.script` reply | `isolation`, `lane`, `laneNote`, `attemptedChanges`, `attemptedChangesCount`, `basedOn` |
| `Connection.respond` | top-level `queue` (waited 250 ms or more); on errors `error.next`, `error.retryAfterMs`; `details.applied` on `cancelled` |
| `busy` details | `reason`, `retryAfterMs`, `queue`, `abandoned` |

Request fields are accepted at any protocol (an unknown field is ignored today, a known one is
honoured); only the **replies** are gated. `health` is available at any protocol (a new command
cannot change an old transcript).

**Capabilities** (object, name to integer version; a new minor feature raises the number and needs no
new protocol): `errorNext`, `expectAll`, `idempotency`, `laneHint`, `maintLane`, `queueInfo`,
`cancelWait`, `forkReport`, `format`, `backup`, `upgradeGate`, `scriptIsolation`, `scriptSha256`,
`attemptedChanges`, `health`, `identity`. A client uses a feature only if its capability is present.
An engine without `capabilities` (hydra.2/3) is "degraded": 7.5.

### 3.2 `hello`/`status` identity block (v3)

New keys are appended after `memory` and before `projects` (their order is part of the v3 golden):

```json
{
  "protocol": 3, "minClient": "1.0.0", "hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3",
  "...": "existing keys unchanged", "memory": {"usedMb": 310, "committedMb": 700, "maxMb": 8192},
  "protocolMin": 2, "protocolMax": 3,
  "capabilities": {"errorNext":1,"expectAll":1,"idempotency":1,"laneHint":1,"maintLane":1,"queueInfo":1,
                   "cancelWait":1,"forkReport":1,"format":1,"backup":1,"upgradeGate":1,
                   "scriptIsolation":1,"scriptSha256":1,"attemptedChanges":1,"health":1,"identity":1},
  "limits": {"maxQuick": 16, "maxLong": 4, "maxMaint": 2, "maxImports": 2, "quickScriptMaxS": 60,
             "cleanupGraceS": 15, "abandonWaitS": 5,
             "maxRunningPerKey": {"quick": 8, "long": 3, "maint": 1}},
  "policy": {"requireBackupForUpgrade": true, "requireExpect": false},
  "paths": {"stateDir": "F:\\...\\state", "instance": "rusticre", "endpointFile": "...", "logFile": "...",
            "scriptPath": [], "tmpDir": "...", "upgradeCacheDir": "...", "install": "..."},
  "platform": {"os": "Windows 11", "osVersion": "10.0.26300", "arch": "amd64", "cpus": 16,
               "javaVendor": "Eclipse Adoptium", "javaVersion": "25.0.4", "maxHeapMb": 8192,
               "fileSystems": {"stateDir": "ReFS", "tmpDir": "NTFS", "upgradeCacheDir": "ReFS"},
               "cow": {"stateDir": true, "tmpDir": false}, "testHooks": false},
  "analysisIdentity": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3", "buildDate": "...",
                       "dbVersions": {"program": 33, "dataTypes": 3},
                       "decompiler": {"path": "...\\decompile.exe", "sizeBytes": 0, "sha256": null}},
  "projects": []
}
```

- `limits` values shown are examples; real ones are the configured slots.
- `analysisIdentity.decompiler.sha256` is `null` until a background hash (computed once, cached
  by path, size and mtime) finishes; `hello` never waits for it.
- `dbVersions.program` is read reflectively from `ProgramDB.DB_VERSION` (`UpgradeCache.java:1056-1065`,
  which returns `-1` on failure). A `-1` is reported as `null`, `health.state` is `degraded`, and
  the DB-version release gate (9) fails. `dbVersions.dataTypes` is `null` until it is read and
  tested against 12.1.4 data (E2); it is never guessed.
- `cow` reuses `ProjectFork.clones` (`ProjectFork.java:138-141`): Windows and ReFS only. No other
  copy-on-write file system is claimed.

### 3.3 Error model

Existing codes and their meanings are unchanged (`SessionException.java:27-51`). Additions:

| Code | When | `details` (besides the ones named) |
|---|---|---|
| `backup_required` | `open_program writable:true upgrade:true` on a non-disposable project whose program is in an older or unknown format, without a valid `backup` | `project`, `program`, `format`, `suggest:"fork_project purpose backup"` |
| `script_changed` | `scriptSha256` does not match the script file | `expected`, `actual`, `script` |
| `bad_request` with `details.field` | unchanged code; v3 adds `field` and `allowed[]` where the value set is closed (`lane`, `isolation`, `purpose`, `verify`) | |

`busy` gains `details.reason` (`slot_wait`, `lock_wait`, `lock_queue_full`, `abandoned`).
`conflict` for `expect` on `signature` and `data_type` has the same shape as for name and comment
(`reason:"changed"`, `address`, `field`, `expected`, `current`, plus `lastEdit` and `holderInfo`
when the journal knows the editor). The fields are `"signature"` and `"type"`.

**v3 error additions** (inside `error`, next to `code`, `message`, `details`):

- `retryAfterMs`: when waiting can help (`busy`). From the lane's median hold time or the lock
  holder's history; clamped to `[250, 10000]`; `1000` when there is no history.
- `next`: a ready request in the same shape as the existing `suggestion` objects, for the cases
  where the engine knows the move. `details.suggest` keeps its string vocabulary unchanged.

Examples (all v3):

```json
{"id":7,"ok":false,"error":{"code":"busy","message":"all 4 long slots are in use (a:b script X.java); retry, or pass a longer \"wait\"",
 "details":{"reason":"slot_wait","lane":"long","slots":4,"queued":3,"waitedMs":10000,"running":["a:b script X.java"],
            "queue":{"lane":"long","position":3,"ahead":2,"estimatedWaitMs":null,"estimate":true}},
 "retryAfterMs":5000},"ms":10003}
```

```json
{"id":9,"ok":false,"error":{"code":"backup_required","message":"swkotor.exe in F:\\...\\kotor was saved by an older Ghidra (program database version 32, this engine 33); upgrading it is one-way and the project is not a disposable fork",
 "details":{"project":"p1","program":"p1:/swkotor.exe","format":{"programDb":{"min":32,"max":32,"current":33},"upgradeRequired":true,"oneWay":true},"suggest":"fork_project purpose backup"},
 "next":{"cmd":"fork_project","project":"p1","purpose":"backup","open":false,"path":"<a folder for the backup>","verify":"hash"}},"ms":4}
```

```json
{"id":12,"ok":false,"error":{"code":"conflict","message":"the signature at 0x401000 is 'void f(void)', not the expected 'int f(int)': someone changed it since you read it",
 "details":{"reason":"changed","address":"0x401000","field":"signature","expected":"int f(int)","current":"void f(void)",
            "lastEdit":{"seq":41,"op":"signature","client":3,"name":"hydralysis","harness":"codex"},
            "holderInfo":{"client":3,"name":"hydralysis","harness":"codex","command":"edit","seq":41},"suggest":"reread"},
 "next":{"cmd":"decompile","address":"0x401000"}},"ms":2}
```

```json
{"id":15,"ok":false,"error":{"code":"cancelled","message":"cancelled while queued for a long slot",
 "details":{"phase":"queued","applied":false}},"ms":812}
```

`details.applied` on `cancelled` is present for `rename`, `comment`, `edit`, `apply_overlay`
(always `false`: they are transactional and cancel only reaches them while queued or before the
transaction), for `script` in owner mode (`applied` = the program's modification number moved,
the existing `changed`), and for `save` (`applied:false`: the stored file is untouched until the
save completes). For other commands the key is absent, not guessed.

### 3.4 Commands

#### `health` (new, inline, any protocol)

Answered on the reader thread like `ping` (add to `Session.isInline`, `Session.java:219-221`) from
a snapshot published by a watchdog thread. It never takes the scheduler lock or any project lock.

```json
{"id":3,"cmd":"health"}
```

```json
{"id":3,"ok":true,"result":{
  "state":"ok","pid":18220,"uptimeMs":3600000,"protocol":3,
  "tick":{"n":3601,"ageMs":420,"lateMs":3},
  "schedulerLockOk":true,
  "lanes":{"quick":{"inUse":1,"queued":0,"oldestWaitMs":0,"longestRunningMs":812,"starving":false},
           "long":{"inUse":2,"queued":3,"oldestWaitMs":41000,"longestRunningMs":600000,"starving":true},
           "maint":{"inUse":0,"queued":0,"oldestWaitMs":0,"longestRunningMs":0,"starving":false}},
  "deadlocked":[],
  "abandoned":[{"program":"p1:/swkotor.exe","cmd":"script X.java","runningMs":412000,"client":"a:b (gone)",
                "stack":["java.lang.Thread.sleep(Native Method)","..."]}],
  "memory":{"usedMb":310,"committedMb":700,"maxMb":8192},"testHooks":false},"ms":0}
```

- `state`: `ok`; `degraded` (an abandoned holder exists, `dbVersions.program` unreadable, or
  test hooks on); `suspect` (the watchdog tick is older than `watchdogStallMs`, or the scheduler
  lock could not be taken in 200 ms, or `ThreadMXBean.findDeadlockedThreads()` returned threads).
  The engine never says `wedged`: the client decides (7.2).
- `tick`: a daemon thread increments `n` once a second and records its own scheduling lateness.
- `schedulerLockOk`: `tryLock(200 ms)` on the scheduler lock. `status` is changed the same way:
  `Scheduler.describe()` takes `lock.lock()` unconditionally today (`Scheduler.java:285-290`), so a
  held scheduler lock hangs `status` too and `status` cannot be a health check. `describe` becomes
  `tryLock(250 ms)` and returns `{"unavailable":true,"waitedMs":250}` when it fails.
- `starving`: `queued > 0` and `oldestWaitMs > starveMs` (30 000 by default).
- `stack`: at most eight frames of the abandoned thread, so an operator can see what it is doing.
- Never claims a long request is a wedge: lane figures are informational.

#### `open_project`, `project`, `info`: `format` (v3)

```json
"format": {"programDb": {"min": 32, "max": 32, "current": 33}, "dataTypeDb": null,
           "upgradeRequired": true, "oneWay": true, "newerThanEngine": false,
           "programsScanned": 1, "truncated": false,
           "engine": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3"}}
```

- Computed by a new static `ProjectFormat` from the same reads as `UpgradeCache.olderFormat`
  (`UpgradeCache.java:986-1042`): the program table's `DB Version` and `Language Version` of
  each program, read from the database header **without opening the program**, cached per
  project `Revision`. At most 64 programs are scanned (`truncated:true` beyond that).
- **Correction to the source designs:** `olderFormat` swallows `IOException` and
  `RuntimeException` and returns `null`, which callers read as "current"
  (`UpgradeCache.java:1032-1036`), and `currentDbVersion()` returns `-1` on failure so that
  `stored < CURRENT_DB_VERSION` is never true. `ProjectFormat` must distinguish
  **unknown** from **current**: an unreadable header or a `-1` constant yields
  `upgradeRequired:null` and the gate treats null as required. `olderFormat` is refactored to
  return the stored numbers (`readStored`) and keep its string for existing callers.
- `newerThanEngine:true` when any stored version exceeds `current`: the engine cannot read it.
  Backups and generations written by a newer engine are detected here.
- It never opens a program and writes nothing; a test checks the project tree hash before and
  after (E2).

#### `open_program` with `writable:true, upgrade:true`: the gate

Added request field `backup`: the path of a backup's `backup.json` (3.6).

```json
{"cmd":"open_program","project":"p2","path":"/swkotor.exe","writable":true,"upgrade":true,
 "backup":"F:\\backups\\kotor\\20261027T143015Z-3fa9c2d1-pre-commit\\backup.json"}
```

Rule (`ProgramCommands.openWritable`, `ProgramCommands.java:408-439`, before `df.getDomainObject`
at `:426`): refuse with `backup_required` when **all** hold: `upgrade` is true; the project is
not disposable (D12); `ProjectFormat` says the program is older or unknown; no valid `backup`.
A `backup` is valid when: it parses; `format == 1`; `kind == "ghidra-session-backup"`;
`verify.ok == true`; `selfSha256` matches the engine's recomputation; `source.revision` equals
`Revision.of` of the project being opened; and every listed file exists with its recorded size.
On success the entry records `upgradeBackup` and a later `save` stamps its comment
`Hydra <release> upgrade from <stored version>; backup <id>`. The `requireBackupForUpgrade`
switch (default true, config and flag) turns the gate off. Opens of forks (`disposable:true`) and of
upgrade-cache copies keep today's path; read-only opens never write and are unchanged.

This is the one **behaviour change visible to protocol 2 connections** (a request that used to
succeed on a canonical older-format project is refused). It enforces what `README.md:1009-1012`
already tells people to do by hand ("do it in a copy"). It is not in the 317-request goldens (they
use no older-format project). Hydralysis itself only upgrades disposable forks (`workcopy.py:312,
377, 394`), so it is unaffected until commit.

#### `fork_project`

Existing fields: `project`, `path` (destination folder or `.gpr`), `name`, `mode`
(`auto|copy-on-write|full`), `writable`, `maxCopyMb`, `wait` (`ForkCommands.java:54-103`).
New request fields (accepted at any protocol):

| Field | Meaning |
|---|---|
| `purpose` | `fork` (default), `backup`, `generation`. Recorded in the sidecar. `fork`: `disposable:true`. `generation`: `disposable:false`, the candidate of a commit. `backup`: a backup. |
| `open` | default `true`. `false` skips registering the fork (required for `backup`). |
| `verify` | `none`, `size`, `hash`; only for `backup`; default `hash`. |

Example, a backup:

```json
{"cmd":"fork_project","project":"p1","path":"F:\\backups\\kotor\\20261027T143015Z-3fa9c2d1-pre-commit",
 "name":"kotor","purpose":"backup","open":false,"verify":"hash","mode":"auto"}
```

v3 reply additions (the success reply today has `method`, `cloned`, `clonedBy`, `bytes`, `files`,
`copyMs`, `freeSpaceUsedBytes`, `depth`, `sidecar`, `ms` and **no** file-system fields; those exist
only in refusals, `ForkCommands.java:262-277` against `:174-197`):

```json
{"project":null,"path":"F:\\backups\\kotor\\2026...","purpose":"backup","method":"clone","cloned":true,
 "cost":{"bytes":128000000,"mb":122.1,"files":14,"sameVolume":true,"sourceFileSystem":"ReFS",
         "destinationFileSystem":"ReFS","cloneCapable":true,"destFreeBytes":91000000000},
 "warnings":["a block clone shares blocks with its source: it protects against a bad commit, not against loss of the volume"],
 "manifest":{"path":"F:\\backups\\kotor\\2026...\\backup.json","sha256":"...","verified":true,"files":14},
 "sidecar":"F:\\backups\\kotor\\2026...\\kotor.fork.json","ms":912}
```

- `cost` is `ProjectFork.Cost.json()` unchanged (`ProjectFork.java:101-109`).
- `warnings[]` states a fork that is a full copy (`cloneCapable:false`: file system and size)
  and, for a backup, `independent:false` (same volume and cloned).
- A backup runs in the MAINT lane (3.5). It keeps every existing guarantee: it is first copied
  into `.<name>.fork-<hex>.tmp` and moved into place (`ProjectFork.java:160-179`), checks
  `Revision.of` before and after (`ForkCommands.java:200-215`), refuses a source another process
  holds writable, and never overwrites. A cancelled or failed backup leaves no project in the
  destination.
- `verify:"hash"` hashes every file of the copy **and** of the source after the copy, and
  compares; `verify.ok` is false on any difference (the copy is left, with `ok:false` in its
  manifest, and the reply is `failed`). Cost: one more read of the project from each side
  (*unmeasured*; KotOR is 122 MB; the 1.5 GB benchmark program is the stress case).
- The sidecar (`.fork.json`, format 1) gains `purpose`, `disposable`, `manifest`.

#### Backup manifest, `backup.json` (one schema, two writers)

Written last, after the files, in the backup folder; never modified afterwards.

```json
{
  "format": 1, "kind": "ghidra-session-backup", "writer": "engine",
  "id": "20261027T143015Z-3fa9c2d1-pre-commit", "purpose": "pre-commit",
  "createdAt": "2026-10-27T14:30:15Z", "createdBy": {"client": "hydralysis", "harness": "claude-code"},
  "source": {"gpr": "F:\\...\\kotor.gpr", "name": "kotor", "revision": "3fa9c2d1aa01bb42",
             "lineage": "L-9c1e", "generation": 2},
  "engine": {"hydraVersion": "12.3-hydra.4", "ghidraVersion": "12.3",
             "dbVersions": {"program": 33, "dataTypes": 3}},
  "stored": {"programDb": {"min": 32, "max": 32}, "programs": 1, "scanned": 1, "truncated": false},
  "files": [{"path": "kotor.gpr", "size": 1234, "sha256": "..."}, {"path": "kotor.rep/...", "size": 0, "sha256": "..."}],
  "filesetSha256": "...",
  "copy": {"method": "clone", "sameVolume": true, "sourceFileSystem": "ReFS", "destinationFileSystem": "ReFS",
           "independent": false, "ms": 812},
  "verify": {"level": "hash", "ok": true, "at": "2026-10-27T14:30:17Z", "sourceRevisionAfter": "3fa9c2d1aa01bb42"},
  "selfSha256": "<sha256 of this object without selfSha256, keys sorted, separators , and :>"
}
```

- `writer` is `engine` (E2) or `hydralysis` (the Python path used on hydra.2/3 in Y2). The
  schema, hashes and self-hash rule are identical, so a backup made by either is accepted by
  either.
- `independent` is true only for a real copy on a different volume. A block clone on the same
  volume is `false` and the doctor says what that means.
- The files are not touched after writing (read-only attribute set best-effort). Further copies
  of the same backup are recorded in Hydralysis's own append log (4.5), not by rewriting this file.

#### `edit`, `rename`, `comment`, `apply_overlay`: `expect` and `rk`

`expect` already exists for rename, label and comment (`Operations.java:48-60`, calls at `:229,
237, 242, 271`). It is added to the two ops that already compute the old value and never compare
it: `signature` (`oldSig`, `:157`) and `data_type` (`oldType`, `:186`), about six lines.

```json
{"cmd":"edit","program":"p1:/x.exe","ops":[
  {"op":"signature","address":"0x401000","signature":"int f(int a)","expect":"void f(void)"},
  {"op":"data_type","address":"0x403000","type":"char[16]","expect":null}],"rk":"c-4f2a9e"}
```

`expect` is the old signature text (as `getPrototypeString()` renders it) or the old type's
display name; `null` means "no defined data". `withLastEditor` (`EditCommands.java:49-70`) is
extended: today it maps field `name` to `lastAt(.., "name")` and everything else to
`"comment:..."`, which is wrong for `signature` and `type`; it must map them to the journal's
`signature` and `data_type` fields (`Journal.fieldOf`, `Journal.java:122-130`).

`config requireExpect` (default `false`): shared-writer edits without `expect` get `bad_request`
with `details.field:"expect"`. It is a guard for direct clients; Hydralysis enforces
`expect_revision` itself. `struct` and `variable` edits are not engine ops, so their
compare-and-set remains `verify_before` inside RusticQuery (4.2). This gap is stated, not hidden.

`rk` (string, at most 64 characters) on `edit`, `rename`, `comment`, `apply_overlay`: the journal
entry stores it; a second request with the same `rk` on the same program is not applied and
answers `{"replayed":true,"seq":<original seq>, ...the original result fields}`. The window is
the in-memory journal (cap 200 000 entries, `Journal.java:35`), so it does not survive a daemon
restart; that is consistent, because a restart also loses the unsaved edit it would deduplicate.
It is not a durability feature.

#### `script`: lane, isolation, pinning, reply

```json
{"cmd":"script","script":"RusticQuery.java","program":"p1:/x.exe","args":["{...}"],
 "timeout":35,"lane":"quick","isolation":"shared","scriptSha256":"<sha256 of the script file>","wait":180000}
```

- `lane`: `quick` or `long`. `quick` is honoured only when `0 < timeout <= quickScriptMaxS`
  (default 60, hard maximum 120); otherwise the request stays `long` and the reply carries
  `laneNote`. Absent means `long` (today). `Scheduler.laneOf(cmd)` becomes
  `laneOf(cmd, req)`; the deadline is already enforced by `m.deadline(...)`
  (`ScriptCommands.java:75`).
- `isolation`: `shared` (default; the program is shared, the outer transaction is always rolled
  back: `ScriptCommands.java:174-188`), `exclusive` (the program's write lock for the run, today's
  `"exclusive":true`, `:92`), `private` (3.7).
- `scriptSha256`: if present, the engine hashes the resolved script file (cached by path, size
  and mtime) and refuses a mismatch with `script_changed`. Hydralysis sends it for RusticQuery, so
  a planted or stale file in the staged script folder cannot run under the shared read lock.

v3 reply additions:

```json
{"script":"...\\RusticQuery.java","mode":"contained","isolation":"shared","lane":"quick",
 "program":"p1:/x.exe","seconds":0.31,"chars":812,"truncated":false,"output":"...","changed":false,
 "unsaved":false,"attemptedChanges":false,"attemptedChangesCount":0}
```

`attemptedChanges` is the program's modification-number delta **measured before the rollback**
(`runScript` reads `modBefore` at `:172` and today reports `changed:false` by construction when
contained, `:195-196`). In `shared` mode it is a program-wide indicator, not a per-script one:
with several shared scripts running at once, one script's rolled-back write can show in another's
delta. A non-zero value for a RusticQuery read action is a test failure in Hydralysis (7.4).

#### `cancel`

Unchanged request and reply. The v3 addition is on the **cancelled request's** error
(`details.phase`, `details.applied`, 3.3).

#### Every queued request: `queue`

A v3 success reply that waited 250 ms or more for a slot carries, next to `result` and `ms`:

```json
{"id":5,"ok":true,"result":{"...":"..."},"ms":4210,"queue":{"lane":"long","waitedMs":4000,"positionAtStart":3}}
```

While it waits, the existing progress event carries `queue` (the plumbing exists:
`RequestMonitor.waiting(what, queueInfo)`, `RequestMonitor.java:98-101`, and `:191-193`, but
`Scheduler.admit` calls the one-argument form, `Scheduler.java:155`):

```json
{"event":"progress","id":5,"message":"waiting for a long slot","queue":{"lane":"long","position":3,"ahead":2,"estimatedWaitMs":null,"estimate":true}}
```

### 3.5 Lanes and admission rules

| Lane | Commands | Slots (config) |
|---|---|---|
| `quick` | `list`, `functions`, `decompile`, `rename`, `comment`, `open_program`, `switch`, `open_project`; **`script` only with `lane:"quick"` and a bounded `timeout`**; `health`, `ping`, `status`, `cancel` need none | `maxQuick` (CPU count) |
| `long` | `analyze`, `import`, `script` (default) | `maxLong` (CPU/4, at least 2) |
| `maint` (new) | `fork_project`, `refresh`, `reopen`, `promote_overlay`, `save` | `maintSlots` (2) |

`save` moves from long to maint: a 35 s save of the 1.5 GB benchmark program (*unmeasured on this
machine*, from the durable-annotations analysis) must not wait behind two analyses, and a
Hydralysis commit that holds `.commit.lock` must not queue behind a four-hour analysis. This is a
behaviour change for v2 connections that has no reply-shape effect (v2 `status` does not list the
`maint` lane). `import` and `analyze` stay long. `ImportGate` keeps its own queue and its own
estimate, labelled `estimateScope:"load"` because it excludes analysis; it is not rewritten.

**Fair key.** The round-robin map in `Scheduler.State.queue` is keyed by connection id
(`Scheduler.java:84,152`). It becomes keyed by `connection id + Caller.Identity.scope()`
(`Caller.java:44`), so ten harnesses multiplexed over one Hydralysis connection are ten queues.
Unlabelled requests share one key per connection, as today. The key is attribution, not access
control (any holder of the token can forge it; the README already says so).

**Per-key running cap**, work-conserving: it applies only while another key waits for that
lane. Defaults: quick `max(1, slots/2)`, long `max(1, slots-1)`, maint `1`. It is one extra
condition in `admit` and in `release`'s hand-over loop (`Scheduler.java:266-277`).

**Queue information.** `Ticket` computes `position` and `ahead` on demand. ETA:
`null` until the lane has recorded 5 completions; then
`ceil((ahead + 1) / slots) * median(last 20 hold times of the lane)`; `null` again when any running
holder has already run longer than 5 times that median (the lane is dominated by a long job and
the median says nothing); always `estimate:true`. This is deliberately crude: the long lane mixes
100 ms scripts and hour-long analyses.

**Validate-before-wait.** `Session.execute` admits first and validates later (`Session.java:248`
against `Access.withProgram`). New `Requests.preflight(cmd, req)` runs the request-shape checks
(missing or ill-typed fields, unknown `op` kinds, bad `lane`/`isolation`/`purpose`/`verify`, `expect`
types) **only when `admit` would have to enqueue**. A request admitted at once keeps today's
order of errors, so no existing golden changes.

**Import wait fix.** `ImportCommands` waits for the import gate without a deadline, then calls
`scheduler.admit(c, "import", m, waitMs(req))` and `lockProject(p, false, waitMs(req), "import")`
(`ImportCommands.java:112-114`) with `waitMs` defaulting to 10 s (`Requests.java:30`): an import
that waited an hour for its turn can fail `busy` ten seconds after reaching the front. Both calls
take the remaining wait computed from `limited`/`deadline` (`:79-81`), unlimited when unlimited.

**Cancel-aware lock waits.** `Caller.enter(c, id)` (`Caller.java:86`, called from
`Connection.respond`) also stores the request's `RequestMonitor`; `Caller.monitor()` returns it. A new
static `Waits.tryLock(Lock, waitMs)` polls `tryLock` in 100 ms slices and aborts on
`monitor.isCancelled()` or `client.leaving`. It replaces the three request-bound waits
(`Access.lockProject`, `Access.java:109`; `ProgramEntry.acquire`, `ProgramEntry.java:195`; the
overlay lock, `OverlayCommands.java:142`) without changing any signature. The cleanup waits
(`CLEANUP_WAIT_MS`: `ProgramCommands.java:622`, `ProjectCommands.java:408`) are not request-bound
and are handled by the dead-client rule below.

**Lock-queue cap (opt-in).** For a request that carries `lane:"quick"`, at most
`max(2, slots/2)` may wait on one program's lock (`ProgramEntry.waiters`); further ones get `busy`
at once with `reason:"lock_queue_full"` and a `retryAfterMs`. The wait then happens in the client
(Hydralysis already treats `busy` as retryable and has its own budget), not in an engine slot.
Parking a waiter's slot is **not** attempted: it breaks "lock holders never wait for a slot"
(`Scheduler.java:42-43`), which is what makes slot-then-lock deadlock-free, and it needs a written
lock order and a stress test of its own.

**Dead clients: bounded release.** `Connection.run` (`Connection.java:93-108`) cancels the
client's requests, then `awaitTermination(1, HOURS)` on both executors before
`session.disconnect`. Replaced by: cancel; wait `cleanupGraceS` (15); `shutdownNow()` (interrupts
lock waits and I/O, not busy loops); wait `abandonWaitS` (5); then call `session.disconnect`
regardless. And `disconnect` itself must not wait 600 s: `Session.disconnect` passes
`CLEANUP_WAIT_MS` to `leaveProject` (`Session.java:121`), whose `lockProject` and
`releaseUse` calling `e.acquire(true, wait)` use that wait. For a leaving client both use
`abandonWaitS`; if the exclusive lock cannot be had, the program entry is flagged
`abandoned {cmd, since, thread, client}` and:

- the dead client's ownership bits (`owner`, `writers`, `users`, which are guarded by
  `synchronized (e.users)`, not by the program lock) are removed so it no longer blocks others;
  if that cannot be made safe in E3b's review, the fallback is to leave them until the holder ends
  and still report `abandoned`;
- other requests for that program get `busy {reason:"abandoned", holderInfo:"abandoned request
  <cmd>, client gone, running N s"}` immediately instead of a silent wait;
- `status.programs[].abandonedRequests[]` and `health.abandoned[]` list it;
- **the program object is not disposed** while the abandoned thread runs (`Session.reap` already
  uses non-blocking `tryLock`, `Session.java:194-199`, so it cannot).

What this cannot do: Java cannot kill a thread that ignores cancel and interrupt, and cannot
unlock a `ReentrantReadWriteLock` held by another thread. A non-cooperative script keeps its
program lock after its client is gone; the design bounds the wait, makes the state visible and
keeps everything else running. The only hard remedy is a helper JVM for user scripts, which is out
of scope and said so in the README. `RusticQuery` calls `monitor.checkCancelled()` at 17 sites
(`RusticQuery.java:126, 254, ...`); new loops must call it.

**Orphan TTL (E3b, optional, default off).** With `orphanKeepS > 0`, `Session.reap` ages the
unsaved edits of a shared program whose last writer died (`ProgramEntry.holdsOrphanedWork`,
`orphanedSince`, `Session.java:171`), writes `<stateDir>/recovery/<project>-<program>-<ts>.journal.json`
(the `Journal` entries, which carry old and new values, plus revision and sha256), then discards.
Hydralysis never needs it (its work copies are replayable from the store).

### 3.6 Script isolation

| Mode | What runs on what | Readers | Sees unsaved shared edits | `attemptedChanges` |
|---|---|---|---|---|
| `shared` (default) | the shared `Program`, shared read lock, outer transaction rolled back | not blocked; may observe transient writes of a script that mutates | yes | program-wide delta (approximate under concurrency) |
| `exclusive` | the shared `Program`, its write lock, outer transaction rolled back | blocked for the run | yes | exact |
| `private` | a throwaway program object from the **stored** file | not blocked, never see it | **no** (`unsavedIgnored` in the reply says how many edits it missed) | exact |

`private` reuses the mechanism of `OverlayCommands.loadOverlay` (`OverlayCommands.java:277-314`:
`getReadOnlyDomainObject`, or `UpgradeCache.openReady` when the shared program came from the
cache): extracted to `PrivateInstance.java`, with a transient consumer, disposed in a `finally`,
never put in the `overlays` map. The extraction touches `OverlayCommands`, so E4 follows E3b. Open
cost is the README figure for an unedited overlay (26-116 ms, +54 MB on the benchmark program)
and is *unmeasured on KotOR*: `private` becomes the Hydralysis default for `ghidra_run` only
after that measurement (7.4). Reply adds `"basedOn":{"saved":true,"programRevision":"..."}` and
`"unsavedIgnored":0`.

A spike in E4 tests whether `Program.lock(reason)` on the shared program turns a mutation attempt
into an exception without disturbing concurrent readers. If it does, `shared` gains enforcement;
if not, the guarantee for `shared` stays "rolled back, measured, and RusticQuery is source-controlled
and hash-pinned", and the README says so. A script is still Java with the daemon's rights: this
is containment of the current program, not a sandbox (`ScriptCommands.java:67`).

### 3.7 Daemon configuration

New keys, in `<state>/config.json`, environment where useful, and command-line flags
(`HeadlessSession.java:64-86`, `README.md:121-150`). All have safe defaults.

| Key | Default | Meaning |
|---|---|---|
| `maintSlots` | 2 | maint lane slots |
| `quickScriptMaxS` | 60 (hard max 120) | longest `timeout` for `lane:"quick"` scripts |
| `maxRunningPerKey` | quick `max(1,slots/2)`, long `max(1,slots-1)`, maint 1 | work-conserving per-key cap |
| `cleanupGraceS` / `abandonWaitS` | 15 / 5 | dead-client release |
| `requireExpect` | false | shared-writer edits need `expect` |
| `requireBackupForUpgrade` | true | the upgrade gate |
| `orphanKeepS` | 0 (never) | orphan dump and discard |
| `watchdogStallMs` / `starveMs` | 15000 / 30000 | `health` thresholds |

`-Dghidra.session.testHooks=true` is not a config key: a launch property only.

### 3.8 Launcher (`support/ghidra_session.py`, P1a and P1b)

- **P1a.** `PROTOCOL = 3`, new `PROTOCOL_MIN = 2`; the hello sends `protocol=3`; `check_compatible`
  accepts a reply in `[PROTOCOL_MIN, PROTOCOL]` and exposes `session.protocol`; the endpoint check
  accepts any overlap of `[2,3]` with `[protocolMin, protocolMax]` (absent: the single `protocol`).
- **P1b.** `SocketSession.call(cmd, deadline=None)`: replaces `sock.settimeout(None)`
  (`ghidra_session.py:845`) for the wait on that reply; on expiry sends `cancel target=<id>` and
  raises `SessionError("deadline_exceeded")`; the connection stays usable. Structured
  `LaunchError` (`:89`, stays a `RuntimeError`) with `code` in `no_jdk | jdk_too_old | bad_install |
  lock_held | heap_too_large | exited_early | no_answer | duplicate_daemon` and `details`
  (`javaMin`, `tried[]`, `logTail`, `holder`, `suggest`). `Daemon.health()`; `Daemon.attach()`
  = `connect(start=False)` (exists: `Daemon.connect(..., start=True)`, `:1004`) for the doctor.
  **Registry**: once the endpoint is ready the launcher writes
  `<userStateRoot>/registry/<sha256(install|stateDir|instance)>.json`
  `{pid, stateDir, instance, install, hydraVersion, startedAt}`; `<userStateRoot>` is the launcher's
  default state root, independent of `-stateDir` (so daemons started with different roots see each
  other; `GHIDRA_SESSION_HOME` relocates it). An entry is live iff its instance lock is held
  (`Daemon.jvm_alive`, `:969-979`). Before spawning, the launcher looks for a live daemon of the
  same install under another state dir. Default policy `warn`: a structured warning in the connect
  result. `singleton:"per-install"` raises `DuplicateDaemonError(holder pid, stateDir, instance,
  three ways out)`. Enforcement is opt-in until the owner consolidates the two live daemons
  (pids 18220 and 17936, which this design never touches). No Java registry class.

---

## 4. The Hydralysis state contract

This section is the contract for what Hydralysis persists. It is implemented in Hydralysis
(packages Y0a, Y1, Y2, Y3); the engine only supplies the commands in section 3. Everything here
works against hydra.2/3 except where a step says it uses an engine capability.

### 4.1 Durable IO rules (Y0a, ships first, no engine change)

A new `src/hydralysis/durable.py` is the only way record-bearing state is written.

1. `atomic_write(path, bytes)`: temporary file in the same directory, write, `flush`, `os.fsync`,
   then replace. On Windows the replace is `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
   MOVEFILE_WRITE_THROUGH)` (documented to return only when the move is on disk); elsewhere
   `os.replace` plus an fsync of the directory. `PermissionError` (Defender, an indexer holding the
   target) is retried with backoff (50 ms doubling to 500 ms, up to 10 s). Whether write-through is
   honoured by the owner's ReFS Dev Drive is **not verified**; no test can cut power. The claims are
   tested by kill -9 and by torn-file injection, and rest on the documented flags.
2. **Sealed JSON.** A record file carries a top-level `seal: {"algo":"sha256","value":...}` over its
   canonical body. A reader that finds a zero-length, unparseable or mis-sealed file falls back to
   `<file>.bak` (the previous sealed version, kept by the writer) and, failing that, raises
   `store_corrupt` with both paths. It **never starts empty** (today `load_store` raises on a
   bad file but treats a missing one as "no edits", `workcopy.py:50-58`).
3. `AppendLog` for CRC32C-framed JSON lines (used by `CURRENT.log`, intent logs, the backup log): each
   append is `crc32c-hex8 SP json LF`, written with `O_APPEND`, then `os.fsync`. A reader takes
   lines in order; an invalid final line is a torn tail and is ignored and reported; an invalid line
   **followed by a valid one** is corruption (4.4).
4. Routed through `durable`: `workcopy._save_store`, `backends.write_json` (and so `targets.register`,
   `working/state.json`, job records in `overlayjobs`), and every new file of 4.4-4.6. A grep gate in the
   test suite fails when a new `write_text`/`write_bytes` of a record appears outside `durable`.
5. Test hook: `durable.fault(name)` is a no-op unless `HYDRALYSIS_TEST_FAULT=<name>:<action>` and
   `HYDRALYSIS_TEST_MODE=1` are both set (actions: `exit`, `raise`, `torn:<n>`).

The evidence database is SQLite in WAL mode (`evidence.py:42-47`) and is already crash-safe; it is out
of scope here.

### 4.2 Store v3: the op-log and the subject record (Y1)

The store stays one JSON file per target and view (`overlays/<key>.json`), at most 20 MiB
(`MAX_HISTORY_BYTES`), rewritten whole under `.sync.lock`. v2 loads and migrates on first write; the
migration only adds keys, writes `<file>.v2.bak` once, and a v2 reader refuses a v3 file
(`record.get("version") not in (1, 2)`, `workcopy.py:57`) so the file is preserved.

```json
{
  "version": 3, "sha256": "<program sha256>", "revision": 41,
  "base": {"lineage": "L-9c1e", "generation": 2, "master_revision": "3fa9c2d1aa01bb42",
           "engine": {"hydraVersion": "12.3-hydra.3", "ghidraVersion": "12.3"}},
  "edits": [
    {"id": "e1...", "address": "0x401000", "options": {"kind": "rename", "name": "Foo", "source": "..."},
     "by": {"client": "hydralysis:123", "harness": "codex"}, "at": 1793100000.1, "batch": null, "seq": 40,
     "effects": [{"subject": "address:0x401000", "field": "name", "before": "FUN_00401000", "after": "Foo"}]}
  ],
  "reverted": [], "journal": [{"revision": 40, "op": "edit", "subjects": ["address:0x401000"], "by": {}, "at": 0}],
  "committed_through": 38,
  "commits": [{"cid": "c-71ab", "generation": 2, "through": 38, "bundle_sha256": "...", "at": 1793100500.0}],
  "stale": null,
  "seal": {"algo": "sha256", "value": "..."}
}
```

- `seq` equals the store revision at append. `journal` keeps its shape and is the cheap rebase
  index; its `subjects` are exactly the **coarse subject** strings of `revisions.subjects_of`
  (`address:0x...`, `type:/path`, `structure:functions`, `*`; `revisions.py:30-48`). Rebase
  (`revisions.reconcile`, `:81-110`) is unchanged.
- **Subject record = one entry of `effects[]`:** `{subject, field, before, after}` plus the edit's
  `seq`, `by`, `at`. `field` is one of `name`, `comment:<type>`, `signature`, `type`,
  `variable:<name>`, `definition` (a struct), `body`, `existence`, `report`. `before` and `after` are
  canonical text: a name, a comment, a prototype string, a type's display name, `sha256:<hex>` of a
  structure definition, `absent` for none. Bulk kinds (`import_types`, `import_archive`) record one
  effect `{subject:"*", field:"report", before:null, after:"sha256:<report>"}`; drift for them is
  checked by input hash (corpus or archive sha256, already stored), not per subject.
- Where it comes from: `RusticQuery.java`'s `typeEdit` already reads the old value for each kind it
  applies; **`effects` output does not exist today** (nor `verify_before` nor `annotation_probe`:
  `RusticQuery.java:2305-2345` returns only `applied`, `import_report`, `overlay_state`). Y1
  adds them. This is the largest piece of Java in the Hydralysis train and is sized accordingly.
- v2 records get `effects: null` and `before_unknown:true`; a commit that includes them needs
  `allow_unverified_before:true`.
- The same record serves: (a) rebase (journal strings); (b) drift at commit (`before` against a
  read-only probe of the master); (c) bundles (4.7); (d) publish and merge (4.8); (e) evidence
  provenance: `evidence_add` records `{view, seq, lineage, generation, hydraVersion}` and a claim
  citing a subject can later be flagged `superseded` when the subject's latest effect moved.
- **Replay set.** The working copy replays `pending = edits with seq > committed_through`, and the
  program's `overlay_state` marker (`RusticQuery.java:2300-2339`; `workcopy.state_of`, `:83-91`)
  includes `committed_through` so a program built before a commit is never reused as if it were
  current. Without this, a commit would be applied twice.
- `revert` of a record at or below `committed_through` is refused (`already_committed`); undo it with
  a new inverse edit or `commit_revert`.

**Journal = recovery = commit source, stated once.** The store is written, sealed and fsynced
inside `.sync.lock` **before** `edit()` returns (`workcopy.py:543-554`). So (1) an acknowledged edit
is in the record; (2) the only crash window is "applied to the working copy but not yet stored",
which is self-healing: the program's marker then claims more records than the store has,
`_prefix_matches` returns `None` (`workcopy.py:341-349`) and the next sync rebuilds from the store;
(3) the commit reads the same record set. There is no second log. The edit's lifecycle: `proposed`
(request) -> `applied` (working copy, in the daemon) -> `recorded` (sealed store; the acknowledgement)
-> `committed` (at or below `committed_through`) -> `superseded` (a later generation changed the
subject).

### 4.3 Idempotency in the client (Y0b)

`hydra.Engine.call` retries **every** command once after `closed` (`hydra.py:268-287`). That is
correct for reads and wrong for a mutating call whose reply was lost. Rules: reads, opens, `status`,
`hello` and `script` with a read action are retried; `script apply_overlays`, `save`, `import`,
`fork_project`, `edit`, `rename`, `comment` are **not**: they raise `EngineError` with
`code:"closed"`, `details.ambiguous:true`, and the caller reconciles (`_sync` re-reads the marker;
`fork_project` checks whether the destination appeared). Hydralysis edits are identified by their
`id`; a commit by its `cid`.

### 4.4 Lineage and generations (Y2)

Layout, under the Hydralysis root (not beside the project: adoption never writes the project
folder; the root is on the owner's Dev Drive so forks are block clones, and `generations_root` can
override it, with a doctor warning when it is not the volume of the current generation):

```
<root>/lineages/<lineage id>/
    lineage.json                {format, id, origin_key, origin_gpr, program, sha256, createdAt}
    CURRENT.log                 append-only, CRC'd lines
    commits/<cid>.intent.log    CRC'd lines (4.6)
    backups.log                 CRC'd lines (4.5)
    gen/0002/<name>.gpr, <name>.rep, <name>.fork.json, MANIFEST.json
    .commit.lock                OS lock: one commit per lineage
```

Generation 0 is the adopted project in place, never written. `CURRENT.log` line:

```json
{"seq":3,"gen":2,"cid":"c-71ab","reason":"commit","gpr":"<root>\\lineages\\L-9c1e\\gen\\0002\\kotor.gpr",
 "manifestSha256":"...","engine":{"hydraVersion":"12.3-hydra.4"},"at":"2026-10-27T15:00:00Z","prevHash":"..."}
```

`reason` is `register`, `commit`, `rollback` or `recover`. The reader takes the last valid line.

- **Torn tail** (the last line fails its CRC and nothing valid follows): ignored, reported in
  `status` and the doctor. It can only show an older, consistent state, because the line is
  forced before any acknowledgement or later step.
- **Mid-log gap** (an invalid line with valid lines after it): `lineage_corrupt`. Reads resolve to
  the last good line before the gap with the error shown on every `status`; commits and reverts are
  refused until the owner repairs it. Silent repair is not done.
- `MANIFEST.json` in a generation folder: `{format, cid, base:{generation, revision}, engine,
  dbVersions, files:[{path,size,sha256}], filesetSha256, backups:[manifest sha256...], store:{revision,
  through, bundle_sha256}, selfSha256}`. **A generation folder is invisible until its manifest
  exists and verifies**; it is built directly in its final folder, so no rename publishes it.
- **Registry is a cache.** `targets.json` records `lineage: {id, origin_key}` and keeps `gpr`
  as the adopted path. `targets.resolve` (`targets.py:90-111`) returns `gpr` from `CURRENT.log`
  and **`key` from the stored `origin_key`** (D11), so overlay stores, working directories and
  view keys survive a flip. A crash between the `CURRENT.log` append and any `targets.json` write is
  harmless. `query.stop` (`query.py:224`) releases the programs of every generation.
- Existing targets with no lineage resolve exactly as today (`key = target_key(gpr, program)`).
  The lineage is created lazily at the first commit; creating it records the current key.

### 4.5 Backups (Y2 on hydra.2/3, switched to the engine's by Y4d)

- Policy (Hydralysis config): `backup_roots: [{path, mode: auto|copy, required}]`
  (first is primary; a block clone on the same volume), `backup_min_verified` (default 1),
  `backup_min_independent` (default 0; the owner can set 1 for a real copy on another volume such as
  `E:\dev-cold`), `backup_confirm_gb` (default 50: above it a backup needs `confirm_large:true`; the
  machine rule is ask before creating anything over 50 GB).
- A block clone protects against a bad commit, **not** against loss or corruption of the volume. The
  manifest says `independent:false`; the doctor shows the count of independent verified copies.
  Secondary roots are always `mode:"full"` copies (a clone shares blocks with its source).
- Layout `<backup root>/<lineage id>/<UTC yyyymmddThhmmssZ>-<revision8>-<purpose>/` with the project
  files and `backup.json` written last. A folder without a verifying `backup.json` is invisible.
- Before relying on a backup (commit, or the upgrade gate's `backup` argument) the client re-reads and
  re-hashes every file against the manifest with `hashlib` and checks the self-hash. The engine's check
  is the cheap one (3.4); it is not a security boundary.
- `backups.log` records `{id, manifestSha256, root, verifiedAt}` per copy so that a deleted or replaced
  backup is detectable.
- On hydra.2/3 (no `purpose`): `fork_project` into the backup folder with `open` true (the fork is
  registered), then `close_project`; Python hashes and writes `backup.json` with `writer:"hydralysis"`.

### 4.6 Commit as a new generation (Y2)

A commit is a Hydralysis job of kind `commit` (`overlayjobs`/`jobowner`: a worker process, so it
survives the MCP process). Request: `ghidra_query action=type_edit options.kind=commit`.

```json
{"kind":"commit","expect_revision":41,"confirm_one_way_upgrade":true,"on_drift":"refuse",
 "only":{"ids":null,"authors":null},"dry_run":false,"backup":"auto"}
```

Preconditions (checked first, in order; any failure creates nothing): `expect_revision` equals the
store revision; `base.master_revision` equals the current generation's revision, else `master_drifted`
(rebase first, 4.7); a non-empty effective record set; no `before_unknown` records unless
`allow_unverified_before`; `confirm_one_way_upgrade:true` whenever `open_project.format.upgradeRequired`
is true **or unknown** (always the case on hydra.2/3, which has no `format`); `.commit.lock` and
`.sync.lock` held briefly to snapshot `upTo = store.revision`. `dry_run` runs the preconditions and the
drift probe and returns the plan; it has no side effects (tree-hash tested).

The confirmation text names what is lost: after the commit only engines at program DB version >= the
engine's can open the generation. Versions are read from `analysisIdentity.dbVersions`; for the other
Ghidra releases the client uses the repository's `format-matrix.json` (E2), which at this commit
records what `README.md:1001-1002` states (program database 33 on main and 32 in 12.1.4; data type
database 3 and 2) and is checked by the DB-version gate.

Steps. Each step is preceded by a forced line in `commits/<cid>.intent.log`:

1. `PREPARE` - preconditions above.
2. `BACKUP_DONE {backup, manifestSha256}` - a fresh backup of the **current generation** per policy,
   re-hashed. A failed primary aborts. A failed secondary aborts or warns per `backup_min_verified`.
3. `CANDIDATE_RESERVED {gen}` - the generation number is reserved in the log **before** the folder
   exists, so a crash cannot reuse a number for a different candidate.
4. Fork: `fork_project(project=<current generation>, path=gen/000N, purpose:"generation")`; open the
   candidate writable owned by the job only, `open_program writable:true upgrade:true backup:<manifest>`
   (the gate passes because the backup is of this revision; D12/D13). The candidate is never shared.
5. `APPLIED {n, drift[]}` - inside **one transaction** run RusticQuery `apply_overlays` with
   `verify_before:true`: every effect's `before` is compared with the live value before it is written;
   a mismatch rolls the whole transaction back and names the effect. `on_drift`: `refuse` (default,
   nothing is published, the full list is returned) or `skip` (drifted subjects stay pending, the rest
   is applied). There is no `overwrite`. Write the program option `hydralysis_commit {cid, lineage,
   base_generation, through, ids_sha256, bundle_sha256, engine}` (provenance inside the data), `save`,
   `close_project`.
6. `FILES_FORCED` - Python opens every candidate file and `os.fsync`s it (Ghidra's save does not promise
   an fsync; whether it does is **not verified**, so it is done unconditionally).
7. `MANIFEST` - hash every file, write `MANIFEST.json` (forced, write-through replace), then
   `VERIFIED` after: open a **clone** of the candidate read-only and check the program `sha256` equals the
   master's; function count and analysed flag equal; `annotation_probe` on every applied effect gives
   `after == actual` (same normaliser); the decompile of each touched function (default cap 25 per
   effect kind) succeeds and equals the working copy's text (same engine, so identical); and a
   spot-check of 25 functions the commit did **not** touch decompiles identically to the previous
   generation (a regression guard for the engine upgrade). Any failure: `ABORTED`, the candidate is
   left unregistered for inspection, nothing else changes.
8. `PUBLISHED` - append the `CURRENT.log` line and fsync. **This is the commit point.**
9. `FINALIZED` - idempotent, keyed by `cid`, under `.sync.lock`: update the store (`committed_through =
   upTo`, `commits[]`, `base` to the new generation); mark every other view's store stale (4.7); mirror to
   `targets.json`; release the locks.

Edits are **not** blocked during steps 2-7: the commit reads the prefix `<= upTo`; records added
meanwhile stay pending and already stand after the committed ones (their `before` is the post-commit
state).

**Recovery table** (run when a lineage is opened and by `commit --resume`, under `.commit.lock`):

| Last durable intent | Observed | Action |
|---|---|---|
| none or `PREPARE` | no candidate folder | `ABORTED`, nothing to clean |
| `BACKUP_DONE` | a verified backup exists | keep it (it is never deleted), `ABORTED` |
| `CANDIDATE_RESERVED` ... `FILES_FORCED` | a partial or unverified `gen/000N` | invisible (no valid manifest); left in place, listed by `backups`; `ABORTED`; the client may resubmit with the same `cid` as a new attempt |
| `VERIFIED`, no `CURRENT.log` line | a verified, unpublished candidate | left unpublished; a resubmission publishes it after re-hashing against its manifest (opt-in `resume_verified`, default false) |
| `PUBLISHED` written, `CURRENT.log` line torn or missing | CRC fails | before the commit point: `ABORTED` |
| `CURRENT.log` line valid for this `cid` | `FINALIZED` missing | **roll forward**: re-hash the candidate against the manifest named in the line; equal: run step 9; not equal: append a `rollback` line to the previous generation (`reason:"candidate_failed_reverify"`), report |
| `FINALIZED` or `ABORTED` | | done |

`commit_abort` is honoured before step 8; after it the answer is `cancel_too_late`.

**Revert** (`options.kind=commit_revert`): only the latest commit. Check the previous generation's
manifest still verifies; append a `rollback` line; `committed_through` returns to the commit's
previous value (the records become pending again) and every view is marked stale. Restoring from a
backup is `fork_project` from the backup into a new generation folder, verified and registered the
same way; nothing touches an existing folder.

Fault points (`durable.fault`): `commit.after_prepare`, `after_backup`, `after_reserve`, `after_fork`,
`mid_apply`, `after_save`, `after_force`, `after_manifest`, `after_verify`, `before_publish`,
`publish_torn`, `after_publish`, `finalize_mid`. The oracle after every fault run and recovery:
**O1** every file of generation 0 and of the previous generation is byte-identical (tree hash, excluding
`projectState` and lock files); **O2** every acknowledged store revision is present; **O3** `CURRENT.log`'s
last valid line names the old or the new generation and, if new, its manifest verifies and a read-only
open succeeds; **O4** no folder without a verifying manifest is offered anywhere; **O5** resubmitting the
same `cid` yields exactly one effect; **O6** killing during recovery and recovering again reaches the
same state.

### 4.7 When the master generation changes

Other views (a named view forks from the master, not from `shared`; `workcopy.with_view`, `:36-43`):

| Thing | Behaviour |
|---|---|
| The committing view | `committed_through` moves; its working copy is rebuilt from the new generation's base, replaying only the pending records. |
| Other views' stores | `stale: "master_generation_changed"` and `base` unchanged; reads keep answering from their working copy, labelled with the generation they came from; mutations are refused with `stale_view` until `rebase`. |
| `rebase` (`type_edit kind=rebase`) | Per record: drop it if its id is in a commit's `ids` (already in the master); `converged` if the new master's value already equals its `after`; keep if a probe shows the master's value equals its `before`; otherwise list a conflict `{subject, field, before, master_now, after}`. The view's base binding moves only when the list is empty or resolved. The outcome is recorded in one atomic store write. |
| Working copies and bases | Keyed by `(lineage origin_key, generation, master revision, engine release)`; a different key means a different directory (`workcopy._base` keyed by master revision and engine release already, `:304-307`; the key adds the lineage and generation). **One** shared base per key across all views, so a new view costs one clone, one writable open and a replay. A replay that was running against the old base cannot be adopted (its marker names the old base). |
| In-flight exports | They snapshot at start; the header records `{lineage, generation, master_revision, engine release}` and resume is refused if any differ (`exporting.py:115-118` records the engine release and query key today). |
| Open programs of other clients | The old generation is immutable, so their reads stay consistent; they get the existing `refreshed`/`stale` marker through `Session.annotate` only if the registered path changes, which it does not for them. A client that wants the new generation reopens. |
| Runtime sessions and evidence | Not invalidated; provenance names the generation and a claim is flagged `superseded_by_generation` on read. |
| A GUI user saving a generation | `Revision.of` of a generation folder differs from its manifest: the lineage is flagged `tampered`, commits are refused until the owner re-adopts. (`projectState` is already excluded from `Revision`.) |
| The Ghidra GUI opening the original `.gpr` | Sees generation 0 with none of the committed annotations. This is a real regression against in-place commit; owner decision O2. |

### 4.8 Publish and merge between named views (Y3, client only)

`type_edit kind=publish|merge` with `expect_revision` of the destination. For each effect of the source
view's edits after its `published_through`, compare its `before` with the destination's current value
of that subject. All match: append the edits to the destination with new ids and
`merged_from:{view, id, seq}`; otherwise return conflicts `{subject, theirs, mine}` and accept
`resolve:{<subject>: take_mine | keep}`. Idempotent through `published_through`. Locks of two views are taken in lexicographic order of their keys. **Per-agent default views are not enabled**
(D26).

### 4.9 Annotation bundles (Y1)

`*.hydralysis-annot.json`: `{format, program:{sha256, language, compiler, image_base, name}, base:{lineage,
generation, master_revision, engine, dbVersions}, store:{view, revision, ids_sha256}, records:[{id,
address, va, rva, kind, options, source, by, at, effects}], bundle_sha256}`; the hash is over canonical
JSON (sorted keys, minimal separators) without the hash field; absolute paths and personal data are
stripped; **no game-derived bytes are embedded**. `export_bundle` is read-only (filter by id, author,
revision range). `import_bundle` is a dry run by default: it validates `bundle_sha256`, program `sha256`,
language and compiler, probes every record's `before` against the target, and reports `base_drift`; with
`apply:true` it adds the records to a **named** view as proposals (`imported_from`). It never writes a
generation. Cross-build address mapping stays in `crossbuild.py` and is out of scope.

---

## 5. Compatibility and the release train

**Train.** hydra.3: the upstream merge only (branch `sync/upstream-2026-10-27`, `6d266ebcff`, golden gate
PASS). hydra.4: this design. Inside hydra.4 the engine packages E1 to E5, E6 and the client packages P1a,
P1b each merge to one integration branch, each gated by the characterization run, `daemon_tests`,
`contract_tests` and `session_smoke`; one tag; one Hydralysis pin bump (`hydra.py` `RELEASE`,
`PROTOCOL`, `ASSETS`, `tests/fakehydra.py`) generated by a new `tools/bump_hydra.py` (it does not exist
in the Hydralysis tree today; the source designs assumed it). The release workflow gets a
`workflow_dispatch` dry run first (the hydra.2 release failed once before succeeding, per the critic).

**Matrix** (what "keeps working" means, exactly):

| Client | hydra.2/3 engine | hydra.4 engine |
|---|---|---|
| Any raw JSON-line client speaking protocol 2 | works | works; replies byte-identical (characterization at protocol 2). One deliberate change: the upgrade gate (3.4) |
| stock `ghidra_session.py` 1.0.0 (protocol 2) | works | works at protocol 2 (endpoint says `protocol:2`) |
| `ghidra_session.py` 1.1.0 (protocol 2..3) | works at protocol 2, capabilities absent | full |
| Hydralysis 0.4.x | works (its own pin) | **refuses by its own pin** (`hydra.py:104-105`, `:246-249`) unless `hydra_allow_unpinned`; this cannot be fixed on the engine side and is stated, not hidden |
| Hydralysis 0.5.x (this train) | degraded set (7.5) | full |

The doctor shows connected clients by protocol so a mixed fleet is visible. The legacy window:
hydra.4 and hydra.5 serve protocol 2; whether to refuse it from hydra.6 is for the owner then (O6).

**State formats written by hydra.4 / Hydralysis** (`CURRENT.log`, `MANIFEST.json`, `backup.json`, store v3) carry a
`format` number and are forward-checked: a reader that finds a newer `format` refuses with
`format_unreadable` and says which writer wrote it; it does not guess.

---

## 6. Honest limits

- **Non-cooperative threads.** Java cannot kill a thread that ignores cancel and interrupt, nor release a
  `ReentrantReadWriteLock` from another thread. A script that never polls `monitor.checkCancelled()`
  keeps its program lock after its client is gone. The design bounds the wait, shows the holder and
  keeps the rest of the daemon running; restart is safe for Hydralysis work (the store is the
  record). Only a helper JVM for user scripts would be a hard guarantee; it is out of scope.
- **Copy-on-write is ReFS only** (`ProjectFork.clones`: Windows and ReFS). On NTFS a fork is a full
  copy bounded by `forkCopyLimitMb`; NTFS CI cannot validate ReFS clone claims, so those tests run on
  the owner's Dev Drive and are recorded as manual gate evidence. A clone backup is not protection
  against volume loss.
- **Windows x64 and JDK 25 only.** No Linux or macOS claim is made.
- **No power-cut test.** Durability is by documented flags (fsync, write-through), kill -9 and torn-file
  tests. Directory-entry durability cannot be forced from Java or Python on Windows; the design never
  relies on it (every state is self-validating and the reader picks the last valid record).
- **`Revision.of` is metadata for large files** (size and mtime above 1 MiB): it proves the saved state
  is the same, not that bytes are intact. Integrity is the manifest hash.
- **A backup verifies bytes read back through the OS cache after a flush**, not the media. Latent errors
  are found by re-hashing (`backend backups verify`) and by keeping an independent copy.
- **Bulk edits have no per-subject `before`** (`import_types`, `import_archive`): drift is input-hash based.
  Subject granularity is the address, type path and `structure:functions`; a struct change and a
  prototype that uses it are different subjects (a dependency the rebase cannot see; as in `revisions.py`
  today).
- **The upgrade gate and the backup check are guards against accidents**, not a security boundary: a local
  process with the daemon's rights can forge a manifest.
- **`private` isolation reads the stored file**, not unsaved edits; `shared` `attemptedChanges` is
  program-wide, not per script.
- **ETA is a rough estimate**, `null` without history, and `null` when the lane is dominated by a long job.
- **The GUI** opening the original project does not see committed annotations (4.7).
- **The data-type database version** is `null` until it can be read and tested against 12.1.4 data.
- **Sources of numbers:** save time (about 35 s) and clone/hash costs come from the 1.5 GB /
  243,855-function benchmark; the golden baseline is KotOR (122 MB). Every timing constant here is
  *unmeasured* on the target until the gate-9 measurements are recorded.

---

## 7. Client obligations (Hydralysis)

What Hydralysis must do for the engine contract to hold. Package ids refer to section 8.

### 7.1 Doctor module (`doctor.py`, Y4b)

One module, one shape: `backend action=doctor` (and the CLI). It is read-only and **never starts a JVM
or a daemon**: it reads the endpoint file and the launcher registry, attaches with
`Daemon.attach()` (connect without start) only if the instance lock is held, and calls `hello`/`health`.
Findings are `{id, level, what, why, fix}`; `fix` is a ready tool call or command.
Sections: root and why; engine (pin, release, protocol range, `analysisIdentity`, decompiler hash); JDK
against the required 25; file systems and COW of root, state dir and the volume of the current generation
(warn on the system drive or a non-ReFS volume, say what a fork costs there); daemon (`health`, memory,
restart history); other daemons from the registry; lanes (starving, abandoned holders); lineage
(current generation, `CURRENT.log` torn tail or gap, unfinished candidates, tampered); backups (count,
verified, independent, last, one-way status); stores (stale views, `before_unknown` records); clients by
protocol. Default output is findings only.

### 7.2 Supervisor policy (`hydra.py`, Y4a)

- **Probe** `health` every 5 s while the engine is in use, with a deadline (`deadline_s` of P1b).
- **Wedged** only when the pid is alive **and**, for 3 consecutive probes 5 s apart, one of: no answer
  to `ping`, `health.state == "suspect"`, `tick.ageMs > watchdogStallMs`, `schedulerLockOk == false`.
  A long request is never a wedge; lane figures are informational.
- **Dead** (pid gone, instance lock free): restart.
- **Budget**: 3 restarts per 10 minutes, then `daemon_unhealthy` with the doctor summary and no further
  attempt. Every event is appended to `supervisor.json` through `durable`.
- **`lost_on_restart`.** At each probe the supervisor keeps the last `status` (programs with
  `unsavedEdits`, running jobs). Before restarting a wedged daemon it computes what dies with it:
  programs under `working/` or a commit candidate are *recoverable* (the store or the intent log is the
  record; a marker mismatch triggers a replay); every other program with unsaved edits, and every
  in-flight import or export, is listed in `lost_on_restart:[{program, unsavedEdits, by}]` and marks
  in-flight Hydralysis jobs `lost_on_restart` in their records. A daemon that is merely slow is **not**
  restarted while the list is non-empty, unless the call carries `force:true`.
- Killing a daemon on ReFS can leave project locks for seconds: keep the existing wait for the pid to exit.
- Tests use fresh state roots only. Pids 18220 and 17936 are never touched.

### 7.3 Commit flow (Y2, Y4d)

As 4.6. The client: checks capabilities (`format`, `backup`, `upgradeGate`) and degrades per 7.5;
always supplies `expect_revision`; shows the one-way confirmation text before any step; runs the
commit as a worker-process job and reports `cid`, step and queue position; re-hashes the backup
itself; treats `CURRENT.log` as the truth and `targets.json` as a cache; never writes into a
generation; and after `FINALIZED` tells the caller the new generation and what moved (other
views stale). On engines with `purpose:"backup"` (Y4d) the backup is the engine's, same schema.

### 7.4 View publish and merge, rebase, user scripts (Y3, Y4e)

`rebase`, `publish`, `merge` as 4.7-4.8; a stale view's mutation returns `stale_view` with the rebase
action as `next`. **`ghidra_run`**: passes `isolation:"private"` only when the target's working copy has
no unsaved edits (`info.unsaved == false`) and the capability exists and the measured open cost on KotOR
is accepted; else `exclusive`; on an engine without the capability it behaves as today. It surfaces
`attemptedChanges`, `isolation`, `basedOn`. RusticQuery calls always send `isolation:"shared"`,
`lane:"quick"` with their `timeout`, and `scriptSha256`; a non-zero `attemptedChanges` on a read action
is a test failure.

### 7.5 Capability degrade (engine hydra.2/3)

| Feature | On an engine without the capability |
|---|---|
| lane hint, queue info, `next` | not sent; waits use the existing client budgets |
| `format` | treated as **unknown**: the commit always needs the one-way confirmation |
| backup | Python-written manifest (`writer:"hydralysis"`) over a plain fork |
| `ghidra_run` isolation | stays today's contained mode, no `private` |
| `health` | `ping` with a deadline; wedge detection needs the pid and the lock only |
| `rk`, `expect` on signature/type | not used; Hydralysis does not rely on them |

### 7.6 Lane hints, deadlines, error contract (Y4a, Y0b)

- Reads: `query.run_script` (`query.py:76-91`) adds `lane:"quick"` (its `timeout` already is
  `timeout_s + 5`); `fork_project` and `save` need no hint (they are maint by command).
- Deadlines: a quick-lane call carries `deadline_s` (default 60 s); long-lane calls none. On expiry the
  library sends `cancel` and the client reports `deadline_exceeded`.
- Waits: `BUSY_WAIT_MS` (180 s, `query.py:29`) and `SYNC_LOCK_S` (900 s, `workcopy.py:33`) shrink to a
  patience budget (default 25 s) once the engine reports queue information; beyond it the tool call
  returns the engine's structured `busy` (queue position, `retryAfterMs`, `next`), not a hang. No
  detached-call state is introduced (D24).
- `EngineError` (`hydra.py:51-63`) keeps `holder`, `holderInfo`, `heldMs`, `queue`, `retryAfterMs`,
  `current`, `next`, with lists capped at 5 entries plus `more`.
- Pools: the MCP server splits PE-only tools (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`,
  `callers`, `callees`, `function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_*`) from tools
  that talk to the daemon, so four blocked engine calls (`TOOL_WORKERS = 4`, `mcp.py:22`) cannot starve
  them (Y0c).

### 7.7 The 20 tools: where each feature lives

The 20 tools stay (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`, `callers`, `callees`,
`function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_add`, `evidence_list`, `ghidra_run`,
`ghidra_query`, `backend`, `prepare`, `job`, `runtime`). One catalog epoch in Y0d, before the 0.5.0
tag, then a hash-checked freeze.

| Feature | Carrier |
|---|---|
| edit with `expect_revision`, named view | `ghidra_query action=type_edit options.{kind,expect_revision,view}` (exists) |
| commit, revert, rebase, publish, merge, export/import bundle | `type_edit options.kind = commit | commit_revert | rebase | publish | merge | export_bundle | import_bundle` (no address needed, like `struct` and `revert` today) |
| changes against master, views, lineage, queue, health | `ghidra_query action=status options.show = changes | views | lineage | queue | health` |
| commit/backup/publish jobs | `job` (existing `status`/`cancel`), jobs of kind `commit` |
| doctor | `backend action=doctor` (new enum value, Y0d) |
| list, verify backups and generations | `backend action=backups` with `options.op = list | verify` (new enum value and an `options` bag, Y0d) |
| user-script mode | `ghidra_run options.{isolation, readonly}` (`options` bag added in Y0d; `view` exists) |
| lane hints, deadlines, identity | internal to the client; no schema |
| format, health, platform facts | surfaced in `backend action=status` and the doctor |

Until the engine capability exists a new action returns `{"not_available":"<capability>"}`, not an
error. Running sessions cache tool lists (`mcp.py:45`): after the epoch, features arrive only through
`options`, and `backend help` and the 0.5.0 release notes say a harness restart is needed once.

---

## 8. Work packages

Repos: **Hydra** = `Ghidra/Features/HeadlessSession` in the Hydra Engine repo (paths below are relative
to it; Java is under `src/main/java/ghidra/app/util/headless/session/`, abbreviated `S/`).
**Hydralysis** = `src/hydralysis`. Each package lists: goal; files owned; depends on; parallel with;
protocol surface; tests (Python integration or characterization; new behaviour gets **new** goldens, old
goldens must still pass for unchanged commands); fault injection; acceptance; size (S, M, L).

Conventions that make the waves disjoint:

- E0 adds loaders so each package adds tests in its **own** file: `examples/dt_<package>.py` for daemon
  tests (each exposes `TESTS = {name: fn}`; `daemon_tests.py` imports `dt_*.py`), `examples/char_<package>.py`
  for characterization scenarios, with goldens in `examples/characterization/v3/<scenario>.json`
  (recorded with `--protocol 3`). The seven existing scenarios run at `--protocol 2` and must stay
  `identical`. Every package appends its new files to `certification.manifest` (the `buildHeadless` IP
  check fails otherwise); that file is the one mechanical merge point. Docs: each package edits only its
  row of the status table of this file; README and CHANGELOG are edited by R1.
- `Session.java` is edited by at most one package per wave (E1 in W1, E2 in W2, E3b in W3, E5 in W4).
- Hydralysis hotspot files (`workcopy.py`, `query.py`, `analysis.py`, `hydra.py`, `api.py`,
  `tests/fakehydra.py`) have one owner per wave.
- All engine tests use fresh state roots under `D:/Projects/Hydra/_logs/<stream>/` and a fresh
  `--tmpdir`; they never touch the live daemons.

### Wave plan (compact)

| Wave | Hydra (engine) | Hydralysis | Notes |
|---|---|---|---|
| W0 baselines and hardening | E0 | Y0a, Y0b, Y0c, Y0d | no engine behaviour change; all parallel |
| W1 foundation | E1, P1a | Y1 | E1 and P1a touch disjoint files |
| W2 facts, gates, lanes | E2, E3a | Y2 | E2 owns `Session.java` (the `project` dispatch); E3a owns `Scheduler`, `ImportCommands`, `Requests`, `Connection.respond` |
| W3 robustness | E3b | Y3 | E3b owns `Waits`, `Caller`, `Access`, `ProgramEntry`, `OverlayCommands`, `Connection`, `Session.disconnect`, `leaveProject`, `releaseUse` |
| W4 isolation, health, launcher | E4, E5, P1b | (catch-up) | E4 after E3b (both touch `OverlayCommands`); E5 owns `Session.java` |
| W5 soak and release prep | E6, R1 | | then **gate G** (section 9) |
| W6 adoption on hydra.4 | | Y4a, Y4b, Y4d, Y4e | disjoint files; pin bump in Y4a |
| W7 deferred | | Y5 | only after its preconditions |

### W0

**E0 (Hydra, M): failing tests first and the test loaders.**
Goal: baselines and loaders before any engine change.
Files: `examples/daemon_tests.py` (loader for `dt_*.py`, `--only` over them), `examples/characterization_tests.py`
(`--protocol {2,3}` sent in `hello`; loader for `char_*.py`; goldens dir `characterization/v3/`),
new `examples/dt_baseline.py`.
Depends on: the hydra.3 install (`D:/Projects/Hydra/_engines/hydra-3-candidate`).
Parallel with: Y0a-d.
Surface: none.
Tests (each **must fail on hydra.3 for the stated reason**; a test that does not fail on its premise is
recorded as a finding and dropped, not weakened): `lane_starvation` (`maxLong=2`, two long sleep scripts,
ten RusticQuery-style scripts with a `timeout`: they queue behind the sleeps, `Scheduler.java:61`);
`dead_client_lock_wait` (a client killed while blocked in `wait=3600000` on a program lock stays
registered until the lock frees: `Connection.java:101`); `import_wait` (`maxImports=2`, `maxLong=2`: a
queued import reaching the front fails `busy` after 10 s: `ImportCommands.java:112`);
`script_shared_visibility` (a mutating contained script and a concurrent reader: expected to show the
transient write; if it does not, the premise "readers can observe transient writes" is dropped from
3.6); `fork_save_behind_analysis` (timing of `fork_project`/`save` while the long lane is saturated).
Acceptance: the seven scenarios report `identical` at `--protocol 2`; the five tests fail on hydra.3 as
stated; the loaders work with an empty `dt_*.py` set. Exit codes verified.

**Y0a (Hydralysis, M): durable IO.** Goal: 4.1.
Files: new `durable.py`; `backends.py` (`write_json`); `workcopy.py` (only `_save_store`, `load_store`);
`targets.py` (`register`); `overlayjobs.py` (job record writes); new `tests/test_durable.py`.
Depends on: none. Parallel with: E0, Y0b-d.
Surface: none. Ships in 0.5.x against hydra.2/3.
Tests: torn, zero-length, mis-sealed and missing-with-`.bak` files each return the old or new content,
never empty-as-no-edits; `PermissionError` retry through a monkeypatched replace; the grep gate; v2
store loads. Fault: kill a writer process between tmp write and replace (`durable.fault`).
Acceptance: `store_corrupt` raised, not "start empty"; no record-bearing write outside `durable`.

**Y0b (Hydralysis, S): client retry policy and `EngineError`.** Files: `hydra.py` (retry only
idempotent commands after `closed`, `details.ambiguous`; widened `EngineError`; `Engine.capabilities()`
returning `{}` on protocol 2), `tests/fakehydra.py` (connection drop after a mutating call; busy with
holderInfo), `tests/test_client.py`. Surface: none. Tests: a dropped `apply_overlays` reply is not
re-sent and the marker reconciles; reads are retried. Acceptance: no mutating call is blindly re-sent.

**Y0c (Hydralysis, S): fast/engine pools.** Files: `mcp.py`, `tests/test_mcp_transport.py`.
Tests: four blocked engine calls do not delay `fingerprint` or `disasm`. Acceptance: `MAX_OUTSTANDING`
still answers `busy` with a retry hint.

**Y0d (Hydralysis, S): the one catalog epoch.** Files: `api.py` (`backend.action += doctor, backups`;
`options` bag on `backend`, `ghidra_run`, `job`; pass-through to stub handlers returning
`not_available`), `workflow_help.py`, `tests/test_contracts.py` (catalog hash, `CATALOG_EPOCH`).
Acceptance: `status` and `backend help` report `catalog:{epoch, hash}`; changing the table without
bumping the epoch fails the test. Later packages never edit the schema.

### W1

**E1 (Hydra, M): negotiation, identity, error contract, `expect`, `rk`.**
Files: `S/Session.java` (hello negotiation, `info(c)`, status header; `case` dispatch untouched),
`S/HydraInfo.java`, `S/HeadlessSession.java` (endpoint and `ready`: `protocolMin/Max`; `paths` set at
start), `S/Client.java` (`protocol`, `v3()`), `S/SessionException.java` (all new codes and `next`,
`retryAfterMs` carriers), `S/Connection.java` (`error()` emits `next` for v3), `S/Operations.java`
(`expect` on signature, data_type), `S/EditCommands.java` (`withLastEditor` fields, `rk`),
`S/Journal.java` (`rk`), `S/Scheduler.java` (only the `describe(boolean)` overload, same output),
new `S/Identity.java` (paths, platform, analysisIdentity, cached decompiler hash).
Depends on: E0. Parallel with: P1a, Y1.
Surface: hello block (3.2), endpoint fields, `expect`/`rk` (3.4), `next`/`retryAfterMs`.
Tests: `examples/char_e1.py` new goldens (hello at protocol 3 with paths, versions, hashes masked;
`expect` conflicts on signature and data_type with the same key order as rename; `rk` replay);
`examples/contract_tests.py` (a protocol-2 hello is answered byte-identically to the committed shape;
endpoint `protocol:2` + `protocolMax:3`; a request for 9 is answered 3; absent 2).
Acceptance: seven old scenarios `identical` at protocol 2; the new goldens differ from nothing else;
`dbVersions.program` non-null and equal to the constant.

**P1a (Hydra, S): client library protocol range.** Files: `support/ghidra_session.py` (`PROTOCOL=3`,
`PROTOCOL_MIN=2`, `check_compatible`, endpoint overlap, `session.protocol`), new
`examples/client_compat_tests.py`. Surface: client side of 3.1. Tests: the 1.1.0 client against a fake
protocol-2 server and against the real hydra.3 install (works at 2); against the hydra.4 candidate (3);
an engine that sends `protocolMax` below 2 is refused with both versions named. Acceptance: all pass; the
1.0.0 client still works against the E1 engine (endpoint `protocol:2`).

**Y1 (Hydralysis, L): store v3, effects, bundles.**
Files: `workcopy.py` (v3 load/migrate/save, effects capture in `edit`, `pending`/`committed_through` in
`state_of`), `revisions.py` (effect and field vocabulary), `analysis.py` (new kinds, option validation),
`scripts/RusticQuery.java` (`effects` output, `annotation_probe`, `verify_before` in `apply_overlays`),
`query.py` (`status options.show=changes`), new `annotations.py` (bundles), new
`tests/test_store_v3.py`, `tests/test_bundles.py`, `tests/test_engine_integration.py` (real-engine round
trip, env-gated).
Depends on: Y0a. Parallel with: E1, P1a.
Surface: store v3 (4.2), bundle format (4.9), `changes`.
Tests: v2 to v3 migration is lossless and leaves `.v2.bak`; effects round trip for rename, comment,
signature, type, label, variable, struct; `before_unknown` handling; subject rebase tests unchanged;
bundle export then dry-run import on a fresh target reports hash, sha256 and base drift. Golden: a
RusticQuery `effects` output check on the committed MSVC fixtures. Fault: kill between engine apply and
store write (the marker heals it).
Acceptance: all existing rebase tests green; `verify_before` mismatch rolls the whole transaction back and
names the effect.

### W2

**E2 (Hydra, L): format, backup, gate, fork report.**
Files: new `S/ProjectFormat.java`, `S/ProjectBackup.java`; `S/UpgradeCache.java` (`readStored`, no
behaviour change), `S/ForkCommands.java` and `S/ProjectFork.java` (purpose, open, verify, cost, warnings,
sidecar fields), `S/ProgramCommands.java` (`openWritable` gate, `upgradeBackup`), `S/EditCommands.java`
(`save` comment stamp), `S/Session.java` (`project`/`open_project`/`info` carry `format` for v3),
`S/ProjectEntry.java`; new `format-matrix.json`, `examples/format_gate.py`,
`examples/make_legacy_fixture.py` (builds a small 12.1.4-format project from one of our own generated
PEs with stock 12.1.4; the output is committed; it contains nothing derived from a game),
`examples/dt_e2.py`, `examples/char_e2.py`.
Depends on: E1. Parallel with: E3a, Y2.
Surface: `format`, `fork_project` fields and manifest, gate, `backup_required` (3.4).
Tests: characterization `format_fork` (format on a current-format fixture; a backup fork; sidecar and
manifest masked, key order checked); `daemon_tests` `upgrade_gate` (needs `--legacy-project`: canonical
`upgrade:true` without `backup` gives `backup_required`; stale, unverified, foreign-revision, wrong self-hash
or wrong-size backup is refused; a good one opens; a fork and the upgrade cache are exempt; source tree
hash unchanged on read-only paths), `format_readonly` (tree hash before and after), `backup_fault` (kill the
daemon mid-backup: no folder with a verifying manifest, retry succeeds; corrupt one byte: client re-hash
refuses; engine gate still passes by design, which the test documents), `fork_report` (NTFS asserts
`method:"copy"` and a warning). `format_gate.py` fails when `ProgramDB.DB_VERSION`,
`DataTypeManagerDB.DB_VERSION`, `DataTypeArchiveDB.DB_VERSION`, `ProgramUserDataDB.DB_VERSION` or
`SlaFormat.FORMAT_VERSION` differ from `format-matrix.json` (values on the sync branch: 33, 3, 5, 1, 4).
Acceptance: as the tests; old goldens identical at protocol 2; the data-type DB read is either tested
against the fixture or reported `null`.

**E3a (Hydra, L): lanes, fair key, queue info, import wait, validate-before-wait.**
Files: `S/Scheduler.java` (`laneOf(cmd, req)`, MAINT, fair key, per-key cap, queue info, ETA, history),
`S/ImportCommands.java` (remaining wait), `S/Requests.java` (`preflight`), `S/Connection.java`
(`respond`: `queue` header, `laneNote`), `examples/dt_e3a.py`, `examples/char_e3a.py`.
Depends on: E1. Parallel with: E2, Y2.
Surface: `lane`, `maint`, `queue`, `busy` details (3.5).
Tests: `lane_starvation` now passes (p99 bound recorded from the E0 baseline, not assumed), `maint_lane`
(`fork_project`/`save` start while long is saturated), `fair_key` (two labels on one connection share;
the cap holds only while another key waits), `queue_info` (position, ETA null without history, `estimate:true`),
`import_wait`, `preflight_wait` (a bad request fails at once when the lane is full and keeps its old error
order when it is not). Characterization: `status.scheduler` v3 shape new golden.
Acceptance: old goldens identical at protocol 2; golden decompile diff identical (gate 9.1, run here).

**Y2 (Hydralysis, L): lineage, commit, revert, backups on hydra.2/3, shared base.**
Files: new `lineage.py`, `commits.py`, `backups.py`; `targets.py` (stable key, `CURRENT.log` resolve),
`workcopy.py` (shared base key, `pending`, `stale`, `_directory`), `overlayjobs.py` (kind `commit`),
`exporting.py` (header, resume refusal), `query.py` (`stop`, `status options.show=lineage`),
`api.py` (dispatch only of the Y0d stubs), `tests/fakehydra.py` (fork purposes), new
`tests/test_lineage.py`, `tests/test_commit.py`, `tests/test_engine_integration.py` additions.
Depends on: Y1, Y0a. Parallel with: E2, E3a.
Surface: 4.4-4.7.
Tests: key stability across a generation flip (the overlay store is found); commit preconditions;
`dry_run` has zero side effects (tree hash); a commit on a KotOR-sized fixture produces a verified
generation and an untouched master; revert; one-way confirmation required when format unknown; torn and
gapped `CURRENT.log`; `tampered` detection. Fault matrix: every point of 4.6 with oracle O1-O6, fresh
roots. Golden: **commit round trip** (after-commit touched functions against the working copy; its own
comparison, never mixed with the hydra.3/hydra.4 diff).
Acceptance: all O1-O6 hold at every fault point; two simultaneous commits give one `commit_busy`.

### W3

**E3b (Hydra, L): cancel-aware waits, bounded release, abandoned holders, `applied`.**
Files: new `S/Waits.java`; `S/Caller.java` (monitor in the thread local), `S/Access.java`,
`S/ProgramEntry.java` (waiters, `abandoned`), `S/OverlayCommands.java` (lock site only),
`S/Connection.java` (`run`: grace, `shutdownNow`, disconnect regardless), `S/Session.java` (`disconnect`),
`S/ProjectCommands.java` (`leaveProject`), `S/ProgramCommands.java` (`releaseUse`, `closeEntry`),
optional orphan TTL in `Session.reap`; `examples/dt_e3b.py`.
Depends on: E3a. Parallel with: Y3.
Surface: `cancelled.details.applied`, `busy.reason`, `abandonedRequests`, `lock_queue_full`.
Tests: `cancel_queued` (slot wait and lock wait answer `cancelled` within 1 s), `dead_client_lock_wait`
(kill a client blocked in `wait=3600000`: released within `cleanupGraceS + abandonWaitS + 2 s` for a
cooperative script), `abandoned_holder` (a deliberately non-cooperative script: `abandonedRequests`,
`busy{reason:abandoned}`, the program is not disposed, `health` lists it, nothing waits 10 minutes),
`lock_queue_full`, `applied_flag`. Characterization unchanged at protocol 2.
Acceptance: the ownership-bits question (3.5) is decided in review and recorded; golden diff identical.

**Y3 (Hydralysis, M): rebase, publish, merge.** Files: new `views.py`; `workcopy.py`, `query.py`,
`tests/test_views.py`. Depends on: Y2. Surface: 4.7-4.8. Tests: stale-after-commit; rebase outcomes
clean, converged, conflict; publish idempotent through `published_through`; `stale_view` refusal with
`next`. Acceptance: no conflict outcome is silently resolved.

### W4

**E4 (Hydra, M): script isolation.** Files: `S/ScriptCommands.java` (`lane` note, `isolation`,
`scriptSha256`, `attemptedChanges` measured before the rollback, `basedOn`), `S/OverlayCommands.java`
(`loadOverlay` extracted), new `S/PrivateInstance.java`; `examples/dt_e4.py`, `examples/char_e4.py`.
Depends on: E3b. Parallel with: E5, P1b.
Surface: 3.4 `script`, 3.6.
Tests: a mutating user script with a concurrent decompile reader in each mode (shared: attempted and
rolled back; exclusive and private: readers never see it); the master file hash and revision unchanged;
RusticQuery read actions report `attemptedChanges:false`; `script_changed`; `unsavedIgnored` when the
program holds unsaved edits; **the private open cost on KotOR is measured and written to the test
timings**; the `Program.lock` spike result recorded either way. Golden decompile diff identical.
Acceptance: `shared` unchanged for protocol 2.

**E5 (Hydra, M): health and watchdog.** Files: `S/Session.java` (`isInline`, `case`), new
`S/Health.java`, `S/Watchdog.java`, `S/Scheduler.java` (`describe` with `tryLock`, lane stats),
`S/HeadlessSession.java` (start the watchdog, parse `testHooks`); `examples/dt_e5.py`.
Depends on: E3b (lane stats). Parallel with: E4, P1b.
Surface: `health` (3.4), `debug_stall` behind the launch property.
Tests: `health` answers while a long request runs; a daemon suspended from outside (`NtSuspendProcess`)
is seen by the Python probe as a live pid with no answer; with the hook, `tick.ageMs` grows and
`schedulerLockOk` is false while `ping` still answers; `status` no longer blocks on a held scheduler lock;
`hello.platform.testHooks` true and `health.state:"degraded"` with the hook on.
Acceptance: the hook cannot be enabled from `config.json` or a request.

**P1b (Hydra, M): launcher.** Files: `support/ghidra_session.py` (deadline, `LaunchError`, registry,
`DuplicateDaemonError`, `Daemon.health()`, `Daemon.attach()`), `examples/dt_p1b.py`. Depends on: P1a.
Tests: `launch_errors` (no JDK, JDK 21 against 25, heap above free RAM, lock held, early exit: each a code
and details), `duplicate_daemon` (a second state dir with `singleton:"per-install"` raises; the default
warns), `call_deadline` (a hung call cancels and raises `deadline_exceeded`, the connection survives),
N concurrent launchers start exactly one daemon per root. Fresh roots only.

### W5

**E6 (Hydra, M): soak harness.** Files: new `examples/soak_tests.py`. Depends on: E3b, E4, E5.
12 client processes with distinct labels over mixed work (quick decompiles, quick scripts, long sleeps,
fork and save, cancels), seeded client kills. Pass criteria: no lost, duplicated or reordered
acknowledged edit against the clients' own logs; every queue empty and no program owner left after the
clients exit; quick-lane p99 under the bound recorded by E0 on hydra.3; no `abandoned` holder after
cooperative scripts. PR lane about 2 minutes; nightly longer.

**R1 (both, M): hydra.4 release preparation.** Hydra: `S/HydraInfo.java` (version), `CHANGELOG.md`,
`README.md` (a protocol 3 section pointing here; the new limits; "Protocols" matrix), `ARCHITECTURE.md`
(rows for the new classes), `certification.manifest`, release workflow dry run. Hydralysis: new
`tools/bump_hydra.py` (generates `RELEASE`, `ASSETS` with SHA-256 and sizes, `fakehydra` constants).
**No tag, no push, no release by this stream**; the tag is an owner action. Until then Hydralysis tests
run against the candidate install with `hydra_allow_unpinned`.

### W6

**Y4a (Hydralysis, L): engine adoption and supervisor.** Files: `hydra.py` (capabilities, pin,
`Supervisor`, deadlines), `query.py` (lane hint, shorter waits), `tests/fakehydra.py` (v3 fake: queue
info, `next`, health), `tools/bump_hydra.py`. Depends on: R1, Y0b. Tests: 7.2 policy against the fake and
the real engine (a suspended daemon is restarted within budget; `lost_on_restart` recorded; a slow daemon
with non-recoverable unsaved edits is not restarted); degrade matrix 7.5 against hydra.3.

**Y4b (Hydralysis, M): doctor.** Files: new `doctor.py`, `tests/test_doctor.py`. Depends on: P1b, E5.
Tests: zero daemon spawns and zero engine calls when no daemon exists; cites `hello.paths/platform/
analysisIdentity`; one finding per section of 7.1.

**Y4d (Hydralysis, M): engine backup and format adoption.** Files: `commits.py`, `backups.py`,
`lineage.py`. Depends on: E2, Y2. Switch backups to `purpose:"backup"` (`writer:"engine"`), use
`format` for the confirmation, pass `backup:` to the candidate open. Tests: a Python-written backup is
accepted by the engine gate and the reverse; fault matrix re-run.

**Y4e (Hydralysis, S): `ghidra_run` modes.** Files: `userscripts.py`, `tests/test_query_script.py`.
Depends on: E4. Tests: `private` only on a clean working copy, `exclusive` otherwise; the reply shows
`attemptedChanges`, `isolation`, `basedOn`.

### W7

**Y5 (Hydralysis, M, deferred): per-agent default views.** Preconditions (all): Y3 has soaked; a stable
agent identity exists (`options.as`, replacing `rusticre:<pid>`); view eviction exists (`max_views`);
the named-view cost is measured per phase (`last_sync.phases_ms`, not the single 1.4 s figure). Default
stays `shared` until then.

---

## 9. Release gates

hydra.4 is not tagged by this stream; these are the conditions under which the owner may tag it. Every
gate is a command with a **verified exit code** and a log under `D:/Projects/Hydra/_logs/<stream>/`.
Fresh state roots; the live daemons (18220, 17936) are never touched; no game-derived data enters any repo.

| # | Gate | Pass condition |
|---|---|---|
| 9.1 | **Golden decompile diff**, hydra.3 against the hydra.4 candidate | `tools/golden.py capture` then `diff` on fresh **copies** of KotOR (program pinned by SHA-256, function count read from the engine, not hard-coded: the 8616 seen on 2026-10-27 is an observation) on **both** paths, `production` (RusticQuery, the path agents use) and `explicit`; plus the 8 public MSVC fixtures, profile `fixtures`. Identical on all (hydra.3 against itself is deterministic: 8616 identical). Source tree hash before and after each capture equal. Run after E3a, after E4, and at release. Any difference blocks. The hydra.2-to-hydra.3 difference (one x64 `strncmp` function per fixture, GP-7212) is **not** in this comparison. |
| 9.2 | **Commit round trip** (separate comparison, never mixed with 9.1) | After a commit on the KotOR copy, the touched functions of the new generation decompile identically to the working copy; 25 untouched functions identical to the previous generation. |
| 9.3 | **Characterization** | the seven scenarios `identical` at `--protocol 2`; every v3 scenario golden recorded, reviewed as a diff of additions, committed |
| 9.4 | **Engine suites** | `session_smoke.py`, `contract_tests.py`, `daemon_tests.py` (all, with `--legacy-project`, so `legacy_overlay` and the older-format half of `upgrade_cache` run: the sync stream skipped them), `client_compat_tests.py`, `format_gate.py`; plus the fork tests on a ReFS volume |
| 9.5 | **Soak, 12 clients** | `soak_tests.py` PR lane green; one nightly-length run recorded (E6 criteria) |
| 9.6 | **Upgrade and backup round trip** on the legacy fixture | backup (engine) then gate refusal without it, success with it, on a fork; commit to a new generation; restore the backup alongside; the restored tree hash equals the original; stock Ghidra 12.1.4 opens the restored backup read-only and does **not** open the committed generation (the documented one-way step, shown rather than asserted); source tree hash unchanged throughout |
| 9.7 | **DB-version check** | `format_gate.py` exit 0: the constants (`ProgramDB` 33, `DataTypeManagerDB` 3, `DataTypeArchiveDB` 5, `ProgramUserDataDB` 1, `SlaFormat` 4 on the sync branch) equal `format-matrix.json`; `hello.analysisIdentity.dbVersions` equal them at runtime and are not `-1`. A changed constant without a matrix entry and release note fails the merge, and also fails any future upstream sync |
| 9.8 | **Compatibility** | a raw protocol-2 transcript against hydra.4; the 1.1.0 client against hydra.3 (real install) and a fake protocol-2 server; Hydralysis 0.5.x test suite against hydra.3 (degraded set) and hydra.4; `bump_hydra.py` output verified against the zip SHA-256 |
| 9.9 | **Fault matrices** | Hydralysis commit points (4.6) with oracle O1-O6; engine `backup_fault`; Y0a torn and zero-length files; all green |
| 9.10 | **Measurements recorded before any constant is fixed** | fsync latency per volume (F: Dev Drive on USB NVMe, C:, D:, E: HDD); store write cost at 1, 4, 16 writers; backup hash throughput; clone against copy on KotOR (122 MB) with the 1.5 GB program as a stress case only; private-instance open cost on KotOR; quick-lane p99 with the long lane saturated, before and after; the per-phase named-view cost. `quickScriptMaxS`, grace times, ETA budgets, `SYNC_LOCK_S`, copy limits and the private default derive from these |
| 9.11 | **Hygiene** | every commit authored and committed as `KelpHect <kellhect@gmail.com>` (checked with `git log --format='%an <%ae> | %cn <%ce>'`); `certification.manifest` lists every new file and `buildHeadless` passes the IP check; docs state every limit of section 6 |

## 10. Open owner decisions

Only the choices that are genuinely the owner's. Each has the default this design assumes if no answer
comes, and what it blocks.

| # | Decision | Default | Blocks |
|---|---|---|---|
| O1 | **Backup policy.** Add a second, independent copy by default (for example `E:\dev-cold\...`, a full copy), `backup_min_independent` 1 instead of 0, and who authorises the 50 GB threshold behaviour? A same-volume clone does not survive loss of the volume. | One primary clone, `min_independent` 0, second root opt-in, ask before any copy over 50 GB | Y2 config defaults, Y4d |
| O2 | **Generation mode against the Ghidra GUI.** The GUI opening the original `.gpr` sees none of the committed annotations. Provide a "materialise current generation" action (a COW clone to a path you choose) in Hydralysis, and keep in-place replace permanently out? | Add materialise later (not in this plan); in-place never | the 0.5.0 documentation wording |
| O3 | **Daemon singleton and the two live daemons** (18220 `default` at `F:\dev-cache\hydra-state`, 17936 `rusticre` at `F:\dev-cache\rusticre-latest`): consolidate into one root and enforce `singleton:"per-install"`? Changing the instance id or state dir starts a second daemon, so a Hydralysis rename of `INSTANCE` must wait. | Warn only; no consolidation by this stream | P1b default policy |
| O4 | **Supervisor default.** Auto-restart on dead or wedged daemons within the 3-per-10-minutes budget, refusing while non-recoverable unsaved edits exist? | On, as 7.2 | Y4a default |
| O5 | **Tag and publish hydra.4 and pin Hydralysis to it** (and the visibility of the private Hydralysis repo). This stream creates no tag, release, push or PR. | Not done | R1 follow-up, Y4a |
| O6 | **Legacy window.** hydra.4 and hydra.5 serve protocol 2; refuse it from hydra.6? | Review at hydra.5 | none now |
| O7 | **Per-agent default views and the agent identity** (`options.as`, replacing `rusticre:<pid>`): when, and who may commit when ten agents run (any holder of the confirmation, one integrator identity, or a human-approved flow)? | Not before Y5's preconditions; any caller may commit with the confirmation | Y5 |

Decided here rather than asked (veto by saying so): `minClient` stays 1.0.0 (D4); `save` is in the maint
lane (D16); no inference of the quick lane (D16); commit and publish ride `type_edit` kinds (D25); no
automatic deletion (D28).

---

## Appendix A: code facts and where they were read

Branch `feat/session-extract` @ `b6df709e1e` (Hydra) and `feat/hydralysis-0.5` @ `d0466bc` (Hydralysis).

| Fact | Where |
|---|---|
| Inline commands are `ping`, `cancel`, `status`; `hello` is not inline; admit happens before the command runs | `Session.java:219-221`, `:223-250` |
| `Session.info()` builds both hello and the status header; `PROTOCOL_VERSION = 2`; `CLEANUP_WAIT_MS = 600_000` | `Session.java:319-337`, `:51-52` |
| `disconnect` cancels, then `leaveProject(c, p, true, CLEANUP_WAIT_MS)` | `Session.java:109-129` |
| `reap` uses non-blocking `tryLock` on the project and program | `Session.java:167-214` |
| `laneOf(String cmd)`: `script`, `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay` are LONG; the queue is keyed by `c.id`; `m.waiting(lane + " slot")` has no queue info; `describe()` takes `lock.lock()`; release is round-robin by client | `Scheduler.java:59-69`, `:84`, `:152`, `:155`, `:285-290`, `:266-277` |
| `Connection.run`: cancel, `awaitTermination(1, HOURS)` twice, then `session.disconnect`; `Caller.enter` in `respond`; `annotate` adds `stale`/`refreshed` | `Connection.java:93-108`, `:211-250` |
| Lock waits use `tryLock(wait)` and ignore cancel | `Access.java:105-109`, `ProgramEntry.java:191-196`, `OverlayCommands.java:142` |
| `Caller.enter(Client, Identity)` stores no monitor; `scope()` exists | `Caller.java:41-50`, `:86-90` |
| `RequestMonitor.waiting(what, queueInfo)` exists and feeds progress events | `RequestMonitor.java:93-101`, `:191-193` |
| `expect` is wired for rename, label, comment; `signature` and `data_type` compute `oldSig`/`oldType` without comparing | `Operations.java:48-60`, `:157`, `:186`, `:229-271` |
| `withLastEditor` maps `name` and `comment` only | `EditCommands.java:49-70`, `Journal.java:104-130` |
| Contained scripts: outer transaction always rolled back; `modBefore` read; `changed:false` by construction when contained; `exclusive` flag | `ScriptCommands.java:92`, `:172-196` |
| `loadOverlay` uses `getReadOnlyDomainObject` / `openReady` | `OverlayCommands.java:277-314` |
| `olderFormat` reads `DB Version` and `Language Version` without opening the program, swallows errors to `null`; `currentDbVersion()` returns `-1` on failure | `UpgradeCache.java:986-1042`, `:1056-1065` |
| `openWritable`: `getDomainObject(e, upgrade, false, m)` | `ProgramCommands.java:408-439` |
| `fork_project`: temp folder then move; `Revision` before and after; sidecar; success reply has no file-system fields; refusal `cost` has them | `ForkCommands.java:54-277`, `ProjectFork.java:92-179` |
| `ProjectFork.clones`: Windows and ReFS only | `ProjectFork.java:138-141` |
| `Revision.of`: size and mtime for files above `HASH_LIMIT` (1 MiB); excludes `projectState` | `Revision.java:51-80`, `UpgradeCache.java:98` |
| Import: unlimited gate wait, then `admit` and `lockProject` with the default 10 s | `ImportCommands.java:77-114`, `Requests.java:30-44` |
| Endpoint file and `ready` carry `protocol`; hydra.2 client sends `protocol` in hello and checks equality on hello and endpoint | `HeadlessSession.java:187`, `:356`; `ghidra_session.py:850-852`, `:105-125`, `:1000` |
| `Daemon.connect(start=...)`, `jvm_alive` (instance lock), `LaunchError`, `sock.settimeout(None)` | `ghidra_session.py:1004`, `:969-979`, `:89`, `:845` |
| README rules: additions need no protocol change; protocol "must be equal"; 12.1.4 program DB 32 and data type DB 2 against 33 and 3 | `README.md:986-990`, `:971`, `:1001-1002` |
| `target_key = sha256(resolved gpr + program)`; overlay store, working dir and view key derive from it | `targets.py:114-117`, `workcopy.py:36-47`, `:105-106` |
| `_save_store` and `write_json`: write then replace, no fsync | `workcopy.py:72-80`, `backends.py:50-54` |
| `edit()` stores inside `.sync.lock` before returning; `_prefix_matches` heals a marker ahead of the store | `workcopy.py:543-554`, `:341-349` |
| `_base` keyed by master revision and engine release | `workcopy.py:290-328` |
| `Engine.call` retries every command once after `closed`; `EngineError` keeps only some detail keys | `hydra.py:268-287`, `:51-63` |
| `RusticQuery`: `apply_overlays`, `overlay_state` marker; no `effects`, `verify_before`, `annotation_probe`; 17 `checkCancelled` sites | `RusticQuery.java:2300-2345`, `:126`.. |
| Every query is a `script` call with `timeout = timeout_s + 5` and a 180 s wait | `query.py:76-91`, `:29` |
| `TOOL_WORKERS = 4`, `MAX_OUTSTANDING = 8`, `listChanged: False` | `mcp.py:22-23`, `:45` |
| `ghidra_query` has an `options` bag; `ghidra_run` has `view` but no `options`; `backend` and `job` have none | `api.py:61-137` |
| `tools/golden.py` and `docs/golden-harness.md` exist; no `tools/bump_hydra.py` | Hydralysis tree |
| hydra.3 candidate: `decompile.exe` sha256 starts `4f4680aa1c22`; gate PASS, KotOR 8616/8616 identical to hydra-2 | `t2_impl_gate.json` (stream report) |

## Appendix B: what the source designs got wrong or left out

Found by reading the code; each is handled in the section named.

1. **The target key is derived from the project path** (D11): a generation pointer flip orphans the
   overlay store. Design A said it had not enumerated `targets[].gpr` consumers; B and C missed it.
2. **`Engine.call` retries mutating commands** (4.3), which A rated harmless and B/C patched with a key everywhere.
3. **Dead-client release is not only `Connection.run`**: `leaveProject` and `releaseUse` wait 600 s (3.5).
4. **`olderFormat` returns "current" on any error** and the DB-version constant can be `-1` (3.4).
5. **`Revision.of` is metadata for large files**, so "revision equals" is not an integrity check (D13).
6. **`private` isolation cannot see unsaved shared edits**, which Hydralysis working copies hold (D20, 7.4).
7. **`RusticQuery` has no `effects`, `verify_before` or `annotation_probe`**: A's commit relied on them as if present (4.2, Y1 sized L).
8. **A replayed commit would be applied twice** unless the replay set excludes `committed_through` (4.2).
9. **`laneOf` is static and cmd-only**; the `save`-if-fast heuristic of A needs state the lane decision does not have (D16, D17).
10. **A WAL under the program write lock** (B) protects an edit path Hydralysis does not use (D5).
11. **README's own versioning rule** says additions need no protocol change; none of the designs reconciled it (D2).
12. **The stock client refuses an endpoint of protocol 3**; "old clients keep working" needed `protocol:2` plus a maximum (D3), and RusticRE 0.4.x still refuses by pin (5).
13. **`tools/bump_hydra.py` does not exist**; the designs assumed it (R1).
14. **The generation sidecar hole**: "no sidecar means canonical" exempts every generation from the second on (D12).
15. **Test files would collide**: every package wanted `daemon_tests.py` (D30).
