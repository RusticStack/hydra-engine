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
RusticRE). The one exception is `README.md`: its line numbers are those of the design branch tip
(`design/protocol-3`), where a two-line pointer to this file was inserted at `README.md:538`, so
every README citation below that point is two lines later than at `b6df709e1e` (where it helps, the
cited README phrase is quoted so the line can be found again after the branch moves). Three further
kinds of evidence are cited by path: the characterization and baseline runs of the engine packages
(`D:/Projects/Hydra/_logs/<stream>/`), the review runs (`.../spec-review/`) and the revision-3
experiments (`.../spec-rev3/`: scripts and their recorded output, 3.8 and 7.6). Anything not
marked that way is a proposal. A number marked *unmeasured* has no
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
13. [Revision history](#revision-history)

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
  existing 317-request characterization goldens, and today's behaviour, except for the short list
  of changes in [5.1](#51-every-change-a-protocol-2-client-can-observe) (each there with its reason
  and its own test, because the goldens see replies only). Everything else about 3 is additive.
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
| D2 | `README.md:988-992` says additions need no protocol change; all three designs still bump to 3 | The bump is kept as a **negotiated contract level**, not a break. `hello` echoes the `protocol` the client sends (the hydra.2 client already sends `protocol=2`, `ghidra_session.py:850-852`), within `[2,3]`; absent means 2. Reply keys that only a v3 client can use are produced only for a v3 connection, at the bounded list of sites in 3.1 (thirteen reply-shape conditionals, C1 to C13, enumerated there). Behaviour that a v2 client could notice is gated on the same `Client.v3()` test (six behaviour gates) unless 5.1 declares it v2-visible with a reason and a test. | A v2 connection then stays byte-identical, so the seven existing scenarios (317 requests) remain an exact regression suite for a Java code base with no unit tests. Those goldens see replies only (they exclude progress events, older-format projects and lock timing: `characterization_tests.py` docstring), so each non-reply behaviour has a behaviour test of its own (5.1). The cost is thirteen reply-shape conditionals (C1 to C13, 3.1) plus six behaviour gates (5.1). The alternative (always additive reply keys, re-record goldens under a "superset of old keys" check) is wire-compatible and is the fallback if the **reply-shape** count (13 now, checked by listing C1 to Cn in 3.1) grows past twenty or a gate needs more than `Client.v3()`; it changes no wire rule and cannot replace the behaviour gates. |
| D3 | Endpoint file and `ready` event: protocol 3 only (A), or the lowest served plus a maximum (C) | Endpoint file and `ready` carry `"protocol": 2` (the lowest served), plus `protocolMin: 2`, `protocolMax: 3`. | The stock client refuses the endpoint on inequality (`ghidra_session.py:1000`) and the `hello` on inequality (`:113`). A hydra.4 client library accepts any overlap of `[2,3]` with the daemon's range and uses the highest. So: a hydra.2/3 stock client works against a hydra.4 daemon at protocol 2; a hydra.4 client works against a hydra.2/3 daemon at protocol 2. |
| D4 | `minClient` bump now (B asked), or never | `minClient` stays `1.0.0`. The new client library is `CLIENT_VERSION 1.1.0` (something added). The one bump is reserved for the release that drops protocol 2. | Nothing is non-additive for a client that does not opt in. A bump would reject every existing client for no safety gain. |
| D5 | Persistent op-log: engine WAL/ViewStore (B, C) versus the Hydralysis store (A) | **The Hydralysis store.** No engine-owned op-log in this train. Re-open only if (a) a non-Hydralysis client needs durable engine annotations, or (b) a spike shows bulk ops (`import_types`, `import_archive`, struct) replay on a changeable view program with the same result as the fork-based working copy. | Hydralysis never uses the engine edit path: it forks, then replays RusticQuery `apply_overlays` (`workcopy.py:352-405`, `RusticQuery.java:2305-2345`). The five native engine ops cover rename, label, comment, signature and data_type only; struct, variable, function_create/body/delete and the two bulk imports exist only as RusticQuery code. An engine log would need a second Java implementation of all of them, the biggest risk any design carried. The store already has atomic writes, a monotone revision, per-edit `by`/`at`, a subject journal, and mandatory `expect_revision` with subject-aware rebase (`revisions.py`). What it lacks is hardening (D14), `before` values, a master binding and a commit path, which this design adds. |
| D6 | Three on-disk formats for "journal" (`<project>.journal`, view op-log, `recovery/*.ops.json`) | None of the three. Journal = recovery = commit source = the store v3 record set. An optional dump of an orphaned engine journal to `<stateDir>/recovery/` (E3b, default off) exists only for direct clients. | One format means one reader and one recovery rule. |
| D7 | Two subject/conflict models (store revision plus `before` drift; seq plus subject rebase) | **One subject record** `{subject, field, before, after, seq, by, at}` inside each edit's `effects[]` (4.2). Conflict decisions use the **coarse subject** (the strings of `revisions.subjects_of`, unchanged); `field` only refines drift checks and the probe. | Existing rebase tests stay valid; a rename and a comment at one address still count as one subject for conflicts but are two effects for drift. |
| D8 | Two backup components with different manifests | One: `fork_project purpose:"backup"` implemented in a new `ProjectBackup` class (not inside `ForkCommands`, 278 lines today). One manifest schema with a `writer` field (`engine` or `hydralysis`), so the Python-written manifest used on hydra.2/3 and the engine-written one are the same format. | The commit works before the engine change (H2 in design A) and later switches writer without a format change. |
| D9 | Commit mechanism: fork+replay+publish, promote a fork's DB into `.rep`, or apply and save in place | Fork+replay+verify+publish as a **new generation**. No Ghidra-internals write, no promote, no in-place save of a canonical project. | Nothing in the commit path can corrupt the master; the one-way format step lands on the new generation only. |
| D10 | Commit point: atomic replace of `targets.json` (A), pointer record in an append log (B), `lineage.json` replace (C) | **Append one CRC'd line to `CURRENT.log` and fsync.** `targets.json` is only a cache of it. | Replace-based pointers have no integrity check and no recovery rule; an append log with per-line CRC and a "last valid line wins, a torn tail is ignored by readers and repaired by the next writer on every acquisition of the writer lock (4.1), a mid-log gap is loud" rule does. |
| D11 | **New finding, in none of the three designs:** `target["key"]` is `sha256(resolved gpr + program)` (`targets.py:114-117`) and keys the overlay store (`workcopy.py:46-47`), the working directory (`:105-106`), the view re-key (`:36-43`), the export header (`exporting.py:118`) and `stop()` (`query.py:224`). A pointer flip that changes `gpr` would orphan every store. | The target keeps a **stable `key` for life**: at lineage creation the existing key is stored in the record (`lineage.origin_key`) and `resolve()` returns it; only `gpr` follows `CURRENT.log`. `stop()` releases the programs of every generation of the lineage. | Without this, the first commit silently abandons the analyst's overlay store. |
| D12 | "Canonical" for the upgrade gate: no sidecar (A, C) or not provably disposable (B) | **Decided from the project's own fork sidecar alone, because the engine cannot see `CURRENT.log` (Hydralysis-side).** A project is disposable iff its sidecar (`<name>.fork.json`) exists, parses, has `kind == "ghidra-session-fork"` and does not say `disposable:false`. A sidecar without the field (every hydra.2/3 fork: the sidecar is built at `ForkCommands.java:246-251`) is therefore disposable: that is the hydra.2/3 meaning of a fork and the only way Hydralysis's own base forks stay upgradable. hydra.4 `fork_project` writes `disposable:true` for `purpose:"fork"` and `disposable:false` for `purpose:"generation"` and `"backup"`. A generation made **before** the engine knows `purpose` (a commit on hydra.2/3, Y2) would carry no field and look disposable, so Hydralysis rewrites that sidecar to `disposable:false, purpose:"generation"` through `durable` right after the fork and **before** step 7 hashes the folder (4.6); the rewrite is part of what the manifest covers. No sidecar, an unparseable one, a sidecar write that failed (`ForkCommands.java:255-257` only warns), or any doubt: canonical. | Generations are made by `fork_project`, so "no sidecar" would exempt every generation from the second one on, and "not a published generation" is not decidable in the engine. A sidecar is an ordinary file a local process can edit: the gate is a guard against accidents (section 6). |
| D13 | Backup freshness test | The gate checks `backup.source.revision == Revision.of(project)` **and** the manifest self-hash **and** every file's size. Integrity of content is the manifest's per-file SHA-256, re-verified by the client before it relies on a backup. | `Revision.of` identifies the large database files only by size and mtime (`Revision.java:51-80`, files above `HASH_LIMIT` = 1 MiB are not hashed): it proves "this is the same saved state", not "the bytes are intact". The engine gate is a guard against accidents, not a security boundary against a local process with the same rights. |
| D14 | Durable IO: skipped (A: "proven"), engine-side CRC/WAL (B), not mentioned (C) | **First thing shipped, on hydra.2/3, no engine change:** `durable.py` (fsync before replace, write-through replace on Windows, retry on `PermissionError`, sealed JSON with a previous-version fallback, never "start empty"). | `_save_store` (`workcopy.py:72-80`) and `write_json` (`backends.py:50-54`) do `write_bytes` then `replace` with no fsync: a power cut can leave a zero-length or stale store, which is the only record on hydra.2/3. Counted, not estimated: the AST write gate Y0a shipped (`tests/test_durable.py`, at Hydralysis `589432e`) finds **41** write sites outside `durable.py`: 11 that are not records in the four files Y0a owns (downloads, corpus copies, logs, markers), **8 call sites in 4 record-bearing writers that stay outside `durable`** (`analysis.save_overlay`, `hydra.write_daemon_config`, `runtime._write`, `runtime_worker._write`) and 22 artifact writes (logs, exports, staged copies). The owner of each is the table in 8.2. |
| D15 | Idempotency: `rk`/`opId` everywhere (B, C) versus none (A) | Two parts. (1) The client **stops blindly retrying non-idempotent engine calls** after `closed` (`hydra.py:268-287` retries every command once), and reconciles through the program's `overlay_state` marker instead. (2) The engine's journaled edit commands (`edit`, `rename`, `comment`) accept an optional `rk` and answer a repeat with `replayed:true` (not `apply_overlay`: the engine's overlays have no journal, 3.4). Commit and backup jobs are idempotent by their own id and intent log. | The marker already makes `apply_overlays` recoverable; the blind retry is the real hole. `rk` costs little where `expect` is being added anyway. |
| D16 | Lanes: where `save` goes; explicit hint versus inference | New **MAINT** lane for `fork_project`, `refresh`, `reopen`, `promote_overlay` and `save`. `script` is `quick` **only with an explicit `lane:"quick"` and a `timeout` of at most `quickScriptMaxS`**; no inference from the timeout or from the script's directory. The lane move is **gated on v3** (a v2 connection keeps `save` and the others in `long`, 5.1). | RusticRE 0.4.x already sends `timeout_s+5` (`query.py:91`) but pins hydra.2 and refuses hydra.4, so inference would help no one it could reach; and silent lane changes for unknown clients are not worth a hidden behaviour. (Judges disagreed; this is the safer reading.) |
| D17 | Replace `Scheduler`/`ImportGate` with an `AdmissionController` (B, C), or extend | **Extend.** Fair key, caps, queue info, MAINT lane and the import wait fix are changes inside `Scheduler` and `ImportCommands`. | `laneOf(String)` is static and cmd-only (`Scheduler.java:59-69`), and `Scheduler.admit(c, cmd, m, waitMs)` (`Scheduler.java:138`) is called from two places, `Session.execute` (`Session.java:248`) and `ImportCommands` (`ImportCommands.java:112`). Lane-by-request and validate-before-wait therefore change **two** signatures, `laneOf(cmd, req)` and `admit(c, cmd, req, m, waitMs)`, and both call sites. E1 makes those edits first, as behaviour-free seams (8.1), so that no later package edits `Session.java` for them. |
| D18 | Validate before queueing (C) | **Validate-before-wait:** the request-shape checks run only when the request would otherwise have to wait for a slot, and only for a v3 connection (5.1). | A request that is admitted at once keeps today's order of errors, so no existing golden changes; a v3 request that would sit in a queue for a minute and then fail `bad_request` fails at once instead. A v2 request keeps today's order and timing exactly. |
| D19 | Dead-client release | One design, owned by E3b: bounded wait, interrupt (and cancel delivered to lock waits by interrupting the registered waiting thread, 3.5), then release regardless, **including the 600 s waits in `leaveProject`/`releaseUse`** (found in the code, in none of the designs): `Session.disconnect` passes `CLEANUP_WAIT_MS` (600 000 ms, `Session.java:52,121`) to `leaveProject`, which takes the project lock and the program's exclusive lock with that wait (`ProjectCommands.java:286-322`, `ProgramCommands.java:480-520`). A stuck holder therefore blocks `disconnect` for 10 minutes per program even if `Connection.run` stops waiting. | A bounded `awaitTermination` alone would not release anything. |
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
| D31 | Seams: which package may edit the cross-cutting files | **Seams first, then features.** E1 (W1) builds four small registries and makes the two signature changes of D17, so that later packages in one wave never edit the same shared file: `Advertised` (capabilities, limits, policy, 3.1), `Settings` (config keys, 3.7), `Preflight` (per-command request validators, 3.5), `DbVersions` (the constants behind `dbVersions`, 3.2). Ownership per file and wave is the matrix in 8.1. | The v1 plan said `Session.java` is edited by one package per wave while E2 and E3a both needed it in W2, and E1 needed a constant that only E2 could edit (review B4). |
| D32 | Commit state: watermark or ids | **A committed-id set, not a watermark.** A record is committed iff its id is in the `ids` of a live (not reverted) commit entry; the replay set is every other record, in `seq` order (4.2). `commit` can take a subset (`only`) and `on_drift:"skip"` leaves records pending, so a single `committed_through` number could mark a skipped record as committed. | Review B2. |
| D33 | Deadline on a stalled call against a hydra.2/3 engine (revision 2 said: `session.close()` on a timer) | **Half-close and abandon, chosen by experiment** (7.6): a worker thread owns `send`/`wait`, the caller waits on its own event, `cancel` goes through the same session, then `shutdown(SHUT_WR)`, never `close()`, and the thread and connection are abandoned (at most 8). The client never relies on an EOF or a reply coming back on hydra.3. | `SocketSession.close()` hangs when another thread is in `wait()` (it closes the file objects before it shuts the socket down), measured on the real 1.0.0 object on Python 3.14.7 and 3.15.0; `shutdown(SHUT_WR)` delivers the FIN and `Connection.run` cancels the request, but hydra.3 then waits in `awaitTermination(1, HOURS)`, so only a cooperative request answers; abandoning without the FIN leaks the engine-side client for good. P1b/E3b change this on hydra.4. |
| D34 | Where each Python catalog stub gets its handler (Y0d left `not_available` stubs in `api.py`; the matrix gave `api.py` to Y2 and Y4b only, two packages in W6 needed it) | **A handler registry in `api.py`, built once by Y2 (W2)**; `backups.py`, `commits.py`, `doctor.py` and `userscripts.py` register their handlers and no later package edits `api.py` (8.2). | The seams-first rule of D31 applied to the Python side; it removes the one cell that two W6 packages would have shared. |

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

**The first `hello` fixes the protocol of the connection for its life.** The first request of a
connection is handled synchronously on its reader thread (`Connection.authenticate`,
`Connection.java:187-205`, which calls `respond` itself), before the next line is read, so every
later request, progress event and reply is gated against a value that is already final and no
gating decision can race the handshake. A later `hello` runs on the worker pool (`Session.execute`,
`case "hello"`, `Session.java:230`; `hello` is not inline) and never changes `Client.protocol`
(written once, before the first reply is sent, and then read-only); it is answered with the
connection's own protocol whatever it asks for. A `protocol` that is not a JSON integer (a string,
a float, `true`, `null`) is treated as absent, i.e. 2: the request is not refused, so no existing
client can be broken by the type of the field. This is argued from the code, not run (no protocol-3
engine exists yet); E1's contract tests pin it (a second `hello` asking 3 on a protocol-2
connection answers 2 and adds no v3 key; `"protocol":"3"` answers 2).

**Endpoint file and `ready` event** (`HeadlessSession.java:187`, `:356`):

```json
{"protocol":2,"protocolMin":2,"protocolMax":3,"minClient":"1.0.0","hydraVersion":"12.3-hydra.4", "...":"..."}
```

`protocol` means "the contract a client that knows nothing newer can use". It is deliberately
the lowest served; the honest statement is `protocolMin`/`protocolMax`.

**Where v3 gating applies to replies (the complete list; everything else a v2 reply carries is
byte-identical).** Thirteen reply-shape conditionals, **C1 to C13**, one per row, each a single
`if (v3)` at the one place that builds the key (the number D2 and 5.1 refer to):

| # | The one site | v3-only content |
|---|---|---|
| C1 | `Session.info(c)` (one method builds the hello result and the `status` header) | `protocolMin`, `protocolMax`, `capabilities`, `limits`, `policy`, `paths`, `platform`, `analysisIdentity` |
| C2 | `Scheduler.describe(boolean v3)` (`status.scheduler`; E1 adds the argument, 8.1) | `maint` lane, `waiting[].position`, `waiting[].estimatedWaitMs`, `oldestWaitMs`, `longestRunningMs`, `starving`, `perKeyCap`, and the `{"unavailable":true,"waitedMs":250}` form (the `tryLock(250 ms)` itself is behaviour gate 5, G6) |
| C3 | the program description in `status.programs[]` | `abandonedRequests[]` |
| C4 | `Scheduler.admit`: the `m.waiting(lane + " slot", ...)` call (`Scheduler.java:155`, one-argument today) | the `queue` key of a **slot wait**: in its progress events and in `status.requests[].queue` (3.4) |
| C5 | `ImportGate.queueInfo(e)` (`ImportGate.java:309-315`) | `estimateScope:"load"` and nothing else. The `queue` object and the progress key of an **import** wait **already exist in protocol 2** (`m.waiting("import queue", q)`, `ImportGate.java:188-194`; `status.requests[].queue`, `RequestMonitor.describe`, `RequestMonitor.java:111`) and stay exactly as they are |
| C6 | `ProjectEntry.info(client)` (callers: `openProject`, `ProjectCommands.java:92`; the `project` command, `Session.java:265`; `status.projects[]`, `Session.java:333`, `:427`) | `format` |
| C7 | `ForkCommands.forkProject` success | `cost`, `warnings`, `purpose`, `manifest` (backup) |
| C8 | `ScriptCommands.script` reply | `isolation`, `lane`, `laneNote`, `attemptedChanges`, `attemptedChangesCount`, `basedOn`, `unsavedIgnored` |
| C9 | `Connection.respond`, success | top-level `queue` (waited 250 ms or more) |
| C10 | `Connection.error` (gets the client, E1) | `error.next` and `error.retryAfterMs` |
| C11 | `Connection.respond`, the `cancelled` path | `error.details.applied` and `error.details.phase` (3.3) |
| C12 | the one busy-details helper that `Scheduler.admit`, `Access.lockProject`, `ProgramEntry.acquire` and the overlay lock call | `details.reason`, `queue`, `abandoned` (`retryAfterMs` is **not** a details key: it sits in `error`, 3.3) |
| C13 | the one `bad_request` helper of `Requests`/`Preflight` | `details.field` and `allowed[]` (3.3; today a `bad_request` carries no `details`, `Json.java:36-80`) |

Keys that have **no conditional of their own** because only a v3 request can provoke them (a v2
connection cannot send the field, behaviour gate 1), so no v2 reply can contain them:
`lock_queue_full` (needs `lane:"quick"`), `rk_expired` (needs `rk`), `script_changed` (needs
`scriptSha256`). The v3 error code `backup_required` is a code choice, not a reply key: behaviour
gate 6.

**Behaviour gates (six).** These are not reply shapes, so the goldens cannot see them; each has its
own v2 test (5.1): (1) every **new request field** takes effect only on a v3 connection (one helper
reads it: `purpose`, `open`, `verify`, `lane`, `isolation`, `scriptSha256`, `rk`, and `expect` on
`signature`/`data_type`; a v2 request carrying one is exactly as before); the one exception is
`backup` on `open_program`, which any protocol may present because the upgrade gate applies to every
protocol (5.1); (2) `laneOf(cmd, req, v3)` moves `save`, `fork_project`, `refresh`, `reopen`,
`promote_overlay` to `maint` only for v3; (3) the fair key `connection id + scope` and the per-key
cap apply only to a v3 connection's requests (a v2 request keeps the key `connection id`, 3.5);
(4) validate-before-wait runs only for v3; (5) `describe`'s `tryLock(250 ms)` (C2 is its reply shape); (6) the upgrade gate's refusal is
`conflict` with `details.reason:"backup_required"` for v2 and the code `backup_required` for v3.

`health` is available at any protocol (a new command cannot change an old transcript).

**Capabilities** (object, name to integer version; a new minor feature raises the number and needs no
new protocol): `errorNext`, `expectAll`, `idempotency`, `laneHint`, `maintLane`, `queueInfo`,
`cancelWait`, `forkReport`, `format`, `backup`, `upgradeGate`, `scriptIsolation`, `scriptSha256`,
`attemptedChanges`, `health`, `identity`. A client uses a feature only if its capability is present.
An engine without `capabilities` (hydra.2/3) is "degraded": 7.5.

**Who registers what.** Only E1 owns `hello`/`Session.info`, but every package adds its own
capabilities, limits and policy values. E1 therefore ships the **advertisement registry**
`Advertised.java`: all capability, limit and policy **names** are declared up front (the lists of
3.2; a registration of an unknown name throws, so a typo in a capability, a limit or a policy key
fails a test); a package **enables** its own capability from a class it owns
(`Advertised.capability("queueInfo", 1)` in the `Scheduler` constructor; `limit("maxMaint", supplier)`,
`policy("requireBackupForUpgrade", supplier)` likewise) and never edits `Session.java`.
`Session.info(c)` renders `capabilities`, `limits` and `policy` from the registry, in declaration
order, so key order is stable. The v3 hello golden therefore changes **deliberately once per wave**,
and not only in `capabilities`: `limits` and `policy` grow too (E3a: `maxMaint`, `quickScriptMaxS`,
`maxRunningPerKey`; E3b: `cleanupGraceS`, `abandonWaitS`; E2: `requireBackupForUpgrade`) and
`platform.testHooks` appears in W4 (E5). To keep one package from re-recording another's golden,
`char_e1.py` compares **`capabilities`, `limits` and `policy` as required subsets** (every key E1
itself sets must be present with its value; further keys are allowed and not compared), **masks**
`paths`, `platform` and `analysisIdentity` (hashes, build date, versions and machine facts) and
compares everything else exactly; each later package asserts its own names and values in its own
`char_<package>.py`, `platform.testHooks` is asserted only by `dt_e5`/`cc_e5`, and R1 records the full
release golden of the whole hello. A capability a merged package does not enable is absent, which
is what a client must handle anyway (7.5).

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
- `dbVersions.program` is read reflectively from `ProgramDB.DB_VERSION`. Today that read is
  `UpgradeCache.currentDbVersion()`, **private static** (`UpgradeCache.java:1056-1065`, `-1` on
  failure, stored in `CURRENT_DB_VERSION` at `:107`); E1, which needs it first, moves it into the
  package-visible holder `DbVersions.program()` (same code, same `-1`) and makes `UpgradeCache` call
  it, so E2 builds on a constant E1 already owns (8.1). A `-1` is reported as `null`, `health.state` is `degraded`, and
  the DB-version release gate (9) fails. `dbVersions.dataTypes` is `null` until it is read and
  tested against 12.1.4 data (E2); it is never guessed. `DbVersions.java` is created by E1 with
  `program()` and a `dataTypes()` that returns `null`; E2 fills `dataTypes()` in W2 (8.1 gives it the
  W2 cell of `DbVersions.java`, so the registry needs no other mechanism).
- `cow` reuses `ProjectFork.clones` (`ProjectFork.java:138-141`): Windows and ReFS only. No other
  copy-on-write file system is claimed.

### 3.3 Error model

Existing codes and their meanings are unchanged (`SessionException.java:27-51`). Additions:

| Code | When | `details` (besides the ones named) |
|---|---|---|
| `backup_required` | `open_program writable:true upgrade:true` on a non-disposable project whose program is in an older or unknown format, without a valid `backup`. A **v2** connection gets the existing code `conflict` with `details.reason:"backup_required"` (and the same other details), the code its sibling refusal already uses (`ProgramCommands.java:428-431`), so protocol 2's error vocabulary does not grow | `project`, `program`, `format`, `suggest:"fork_project purpose backup"` |
| `script_changed` | `scriptSha256` does not match the script file | `expected`, `actual`, `script` |
| `bad_request` with `details.field` | unchanged code; v3 adds `field` and `allowed[]` where the value set is closed (`lane`, `isolation`, `purpose`, `verify`), and `field:"expect"` for `requireExpect` (conditional C13, 3.1) | |
| `bad_request` with `details.reason:"rk_expired"` | an `rk` whose multi-op entries were partly evicted from the journal (3.4); only a request that carries `rk` (v3) can get it | `rk`, `foundOf`, `expectedOf` |

`busy` gains `details.reason` (`slot_wait`, `lock_wait`, `lock_queue_full`, `abandoned`) for v3
(conditional C12). `lock_queue_full` can only answer a request that carries the v3-only
`lane:"quick"`. `cancelled` gains `details.phase` (`queued` for a slot wait, `lock_wait`, `running`)
and, for the commands listed below, `details.applied`, both for v3 (conditional C11).
`conflict` for `expect` on `signature` and `data_type` (v3 only, 3.4) has the same shape as for name and comment
(`reason:"changed"`, `address`, `field`, `expected`, `current`, plus `lastEdit` and `holderInfo`
when the journal knows the editor). The fields are `"signature"` and `"type"`.

**v3 error additions** (inside `error`, next to `code`, `message`, `details`):

- `retryAfterMs`: **the one location is `error.retryAfterMs`** (a sibling of `details`, never inside
  it; 3.1, 3.5 and 7.6 all mean this key). Present when waiting can help (`busy`). From the lane's
  median hold time or the lock holder's history; clamped to `[250, 10000]`; `1000` when there is no
  history.
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
(the engine's overlay command: always `false`: they are transactional and cancel only reaches them
while queued or before the transaction), for `script` in owner mode (`applied` = the program's modification number moved,
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
  held scheduler lock hangs `status` too and `status` cannot be a health check. For a **v3** connection `describe`
  becomes `tryLock(250 ms)` and returns `{"unavailable":true,"waitedMs":250}` when it fails; a v2
  `status` keeps the unconditional lock (G6, 5.1).
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

Added request field `backup`: the path of a backup's `backup.json` (schema below). It is read at any protocol, because the gate applies to every protocol.

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

This gate is **declared v2-visible, not gated** (5.1): a request that used to succeed on a
canonical older-format project is refused (with `conflict` for a v2 connection, 3.3), because
protecting the canonical project is the point and a gate only a v3 client meets would protect
nothing from the clients that most need it. It enforces what `README.md:1011-1014` already tells
people to do by hand ("do it in a copy"). The 317-request goldens cannot see it (they use no
older-format project), so a v2 behaviour test against the legacy fixture covers it (5.1). Hydralysis
itself only upgrades disposable forks (`workcopy.py:312, 377, 394`), so it is unaffected until commit.

#### `fork_project`

Existing fields: `project`, `path` (destination folder or `.gpr`), `name`, `mode`
(`auto|copy-on-write|full`), `writable`, `maxCopyMb`, `wait` (`ForkCommands.java:54-103`).
New request fields (read only on a v3 connection, 3.1; a v2 request carrying one behaves as today):

| Field | Meaning |
|---|---|
| `purpose` | `fork` (default), `backup`, `generation`. Recorded in the sidecar. `fork`: `disposable:true`. `generation`: `disposable:false`, the candidate of a commit. `backup`: a backup, also `disposable:false`. |
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
- A backup runs in the MAINT lane (3.5; for a v3 connection, 5.1). It keeps every existing
  guarantee: it is first copied into `.<name>.fork-<hex>.tmp` and moved into place
  (`ProjectFork.java:160-179`), checks `Revision.of` before and after (`ForkCommands.java:200-215`),
  refuses a source another process holds writable, and never overwrites. A cancelled or failed
  backup leaves no project in the destination.
- `verify:"hash"` hashes every file of the copy **and** of the source after the copy, and
  compares. **A failed verify is a failed backup, with one rule for both:** the engine removes
  its own copy exactly as it already does when the source changed during the copy
  (`ForkCommands.java:205-214`: "the copy was removed"), writes no `backup.json`, and answers
  `failed` with `details.verify:{ok:false, mismatches:[{path, expected, actual}]}` (at most 20
  entries). So a published `backup.json` always says `verify.ok:true`; the gate's check of that
  field is a defence, not a state. (The Hydralysis writer on hydra.2/3, 4.5, cannot remove an
  engine-made fork without breaking D28; it simply never writes the manifest, and the folder stays
  invisible and listed by `backups` for manual removal.) Cost: one more read of the project from
  each side (*unmeasured*; KotOR is 122 MB; the 1.5 GB benchmark program is the stress case).
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
  "selfSha256": "<sha256 of the canonical form (below) of this object without selfSha256>"
}
```

- `writer` is `engine` (E2) or `hydralysis` (the Python path used on hydra.2/3 in Y2). The
  schema, hashes and self-hash rule are identical, so a backup made by either is accepted by
  either.
- **Canonical form** (what `selfSha256` and `filesetSha256` hash; both writers must produce the
  same bytes, so it is pinned and does not rely on a library default). UTF-8 without a BOM; no
  whitespace outside strings; separators `,` and `:`; object keys sorted by code point (every key
  of a manifest is fixed ASCII, so code-point and UTF-16 order agree); numbers are integers only
  (no floats, no exponents: sizes and counts fit in 2^53); strings escape exactly the quote, the
  backslash and the control characters U+0000 to U+001F (as `\b \t \n \f \r` where those exist,
  else `\u00xx` with lower-case hex) and **nothing else**: `<`, `>`, `&`, `'`, U+007F and every
  non-ASCII character, including U+2028 and U+2029, are written literally as UTF-8; an unpaired
  surrogate is refused **in a manifest** (it has no UTF-8 form, and a manifest is verified by two
  languages). `filesetSha256` is the sha256 of the canonical form of the `files` array.
  Python writes it with `json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
  sort_keys=True).encode("utf-8")`. Gson cannot be configured to this form (even with
  `disableHtmlEscaping()` it escapes U+2028 and U+2029, and it does not sort keys), so the engine
  writes the manifest with a small canonical serializer in `ProjectBackup` instead of Gson.
  **Test (required, both writers):** a manifest whose `files[].path` holds non-ASCII (an accented
  letter, a CJK name, a supplementary character such as U+1F600) and U+2028 is written by the engine
  and by Python, each is verified by the other, and both match one fixed vector
  (`examples/vectors/canonical-manifest.json` with its expected sha256) checked in both languages.
  The store `seal` and `bundle_sha256` (4.1, 4.9) use the same form but are Python-only, so they may
  contain floats (Python's `repr`) **and tolerate an unpaired surrogate** (Y0a's `canonical()` encodes
  with `surrogatepass`, so a lone surrogate that came from a bad decode in an analyst's note does
  not make the store unwritable; decided in revision 3, a deviation from "refused" that is confined
  to forms nothing outside Python verifies).
- `independent` is true only for a real copy on a different volume. A block clone on the same
  volume is `false` and the doctor says what that means.
- The files are not touched after writing (read-only attribute set best-effort). Further copies
  of the same backup are recorded in Hydralysis's own append log (4.5), not by rewriting this file.

#### `edit`, `rename`, `comment`: `expect` and `rk`

`expect` already exists for rename, label and comment (`Operations.java:48-60`, calls at `:229,
237, 242, 271`). It is added to the two ops that already compute the old value and never compare
it: `signature` (`oldSig`, `:157`) and `data_type` (`oldType`, `:186`), about six lines. Today a
request that carries `expect` on those two ops is **silently ignored**, and the goldens contain no
such request (their `expect` steps are `rename` and `comment` only), so enforcing it for every
protocol would turn a succeeding v2 request into a `conflict` with nothing to catch it. It is
therefore **gated on v3** (behaviour gate 1, 3.1): on a v2 connection `expect` on `signature` and
`data_type` stays ignored, and a v2 behaviour test pins that (5.1).

```json
{"cmd":"edit","program":"p1:/x.exe","ops":[
  {"op":"signature","address":"0x401000","signature":"int f(int a)","expect":"void f(void)"},
  {"op":"data_type","address":"0x403000","type":"char[16]","expect":null}],"rk":"c-4f2a9e"}
```

`expect` is the old signature text (as `getPrototypeString()` renders it) or the old type's
display name; `null` means "no defined data". `withLastEditor` (`EditCommands.java:49-70`) is
extended: today it maps field `name` to `lastAt(.., "name")` and everything else to
`"comment:..."`, which is wrong for `signature` and `type`; it must map them to the journal's
`signature` and `data_type` fields (`Journal.fieldOf`, `Journal.java:117-125`, which returns the
op name for everything but `rename`/`label` and `comment`; `Journal.lastAt`, `:103-114`).

`config requireExpect` (default `false`; applies to v3 connections): shared-writer edits without
`expect` get `bad_request` with `details.field:"expect"`. It is a guard for direct clients; Hydralysis enforces
`expect_revision` itself. `struct` and `variable` edits are not engine ops, so their
compare-and-set remains `verify_before` inside RusticQuery (4.2). This gap is stated, not hidden.

`rk` (string, at most 64 characters; v3 only) on `edit`, `rename`, `comment`: the journal entry
stores it. **Not `apply_overlay`**: the engine's overlay commands have no journal at all
(`OverlayCommands.java` and `Overlay.java` contain none), so there is nowhere to store a key, and
`OverlayCommands.java` is not in E1's files; idempotency of the Hydralysis `apply_overlays` script
action is the `overlay_state` marker (D15, 4.3). The owners are E1 (`EditCommands`, `Journal`;
`Session.java:282` and `:290` are the rename and comment dispatch). What a journal entry stores is a deep copy of the **per-op result**
(`EditCommands.journal`, `EditCommands.java:76-88`: the op's own fields such as `address`, `old`,
`new`, `op`, plus `seq`, `at`, `client`, `name`, `harness`, `cmd`, and now `rk`); it does **not**
store the reply envelope (`applied`, `seqs`, `unsavedEdits`). A second request with the same `rk` on
the same program is therefore not applied and answers a **reconstructed** reply:
`{"replayed":true, "seq":<original seq>, "result":<the stored per-op result>}`, and for a multi-op
`edit` `{"replayed":true, "program":..., "applied":n, "seqs":[...], "results":[<stored results>]}`
with `unsavedEdits` recomputed. It promises the stored fields, not byte equality with the first
reply. If part of a multi-op request's entries has been evicted from the journal, the whole `rk` is
treated as unseen and the answer is `bad_request` `rk_expired` (never a partial replay). The window
is the in-memory journal (cap 200 000 entries, `Journal.java:35`), so it does not survive a daemon
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
  `laneOf(cmd, req, v3)` and the decision (lane and note) is stored on the request's
  `RequestMonitor` by E3a, who owns it; E4's `ScriptCommands` only copies `lane` and `laneNote`
  from the monitor into the reply, so no two packages write the same field (8.1). The deadline is
  enforced by `m.deadline(...)` (`ScriptCommands.java:75`), which only sets the cancel flag: a
  script that never polls it keeps its quick slot past its `timeout` (section 6).
- `isolation`: `shared` (default; the program is shared, the outer transaction is always rolled
  back: `ScriptCommands.java:174-188`), `exclusive` (the program's write lock for the run, today's
  `"exclusive":true`, `:92`), `private` (3.6).
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

While it waits **for a slot**, the existing progress event carries `queue` **for a v3 connection
only** (the plumbing exists: `RequestMonitor.waiting(what, queueInfo)`, `RequestMonitor.java:98-101`,
and `:191-193`, but `Scheduler.admit` calls the one-argument form, `Scheduler.java:155`; E3a passes
the queue information only when the client is v3, so a v2 slot-wait progress event and a v2
`status.requests[]` entry for a slot wait are unchanged, 5.1; conditional C4). This is about the
**slot** wait only: a wait in the **import queue** already carries `queue` in protocol 2 (3.5, C5) and
is not touched:

```json
{"event":"progress","id":5,"message":"waiting for a long slot","queue":{"lane":"long","position":3,"ahead":2,"estimatedWaitMs":null,"estimate":true}}
```

### 3.5 Lanes and admission rules

| Lane | Commands | Slots (config) |
|---|---|---|
| `quick` | `list`, `functions`, `decompile`, `rename`, `comment`, `open_program`, `switch`, `open_project`; **`script` only with `lane:"quick"` and a bounded `timeout`**; `health`, `ping`, `status`, `cancel` need none | `maxQuick` (CPU count) |
| `long` | `analyze`, `import`, `script` (default) | `maxLong` (CPU/4, at least 2) |
| `maint` (new) | `fork_project`, `refresh`, `reopen`, `promote_overlay`, `save`, **for a v3 connection**; a v2 connection keeps them in `long` | `maintSlots` (2) |

`save` moves from long to maint: a 35 s save of the 1.5 GB benchmark program (*unmeasured on this
machine*, from the durable-annotations analysis) must not wait behind two analyses, and a
Hydralysis commit that holds `.commit.lock` must not queue behind a four-hour analysis. This is a
behaviour change, so it is **gated on v3** (behaviour gate 2, 3.1): a v2 connection keeps today's
lane, today's busy text and today's queueing for these five commands, and the two kinds of
connection share one scheduler, so a v2 `save` still queues in `long` while a v3 `save` runs in
`maint` (test `v2_lane_unchanged`, 5.1). `import` and `analyze` stay long. `ImportGate` keeps its own queue and its own
estimate; it is not rewritten. Two things change in it, both E3a's (8.1 gives `ImportGate.java` to
E3a in W2): the estimate gains `estimateScope:"load"` for a v3 connection (it excludes analysis;
conditional C5), and, because `ImportGate.enter` receives only the client **id**
(`ImportGate.java:165`, called with `c.id` from `ImportCommands.java:100`; the `Client` and so
`Client.v3()` are not available inside the gate), `enter` takes the `Client` (or a `boolean v3`) and
stores it on its `Entry`, so that `queueInfo(e)` can decide. What does **not** change: the `queue`
object that an import wait already puts in its progress events (`m.waiting("import queue", q)`,
`ImportGate.java:188-194`) and in `status.requests[].queue` (`RequestMonitor.java:111`) is
**protocol 2 behaviour today**, so it is not new v3 content and not gated: only the `queue` key of
a *slot* wait (C4) and `estimateScope` (C5) are new. `v2_progress_keys` (5.1, G5) pins the exact key
set of both kinds of wait.

**Fair key.** The round-robin map in `Scheduler.State.queue` is keyed by connection id
(`Scheduler.java:84,152`). For a **v3 connection** it becomes keyed by `connection id +
Caller.Identity.scope()` (`Caller.java:44`), so ten harnesses multiplexed over one Hydralysis
connection are ten queues; a v2 connection keeps the key `connection id` (a v2 client that labels
its requests would otherwise see its own requests reordered). Unlabelled requests share one key
per connection, as today. The key is attribution, not access control (any holder of the token can
forge it; the README already says so).

**Per-key running cap**, work-conserving (v3 keys only; a v2 request is never capped): a key at its
cap is held back **only while another key waits for that lane that is itself under its own cap**
(a key that has reached its cap and whose next request is queued does not count as "another key
waiting", so two keys that each run one request and queue another never leave slots idle: with
`maint` slots 4, cap 1 and two such keys, the cap does not apply and both queued requests run).
Defaults: quick `max(1, slots/2)`, long `max(1, slots-1)`, maint `1`. It is one extra
condition in `admit` and in `release`'s hand-over loop (`Scheduler.java:266-277`).

**Queue information.** `Ticket` computes `position` and `ahead` on demand. ETA:
`null` until the lane has recorded 5 completions; then
`ceil((ahead + 1) / slots) * median(last 20 hold times of the lane)`; `null` again when any running
holder has already run longer than 5 times that median (the lane is dominated by a long job and
the median says nothing); always `estimate:true`. This is deliberately crude: the long lane mixes
100 ms scripts and hour-long analyses.

**Validate-before-wait (v3 only).** `Session.execute` admits first and validates later
(`Session.java:248` against `Access.withProgram`). `admit` gains the request
(`admit(c, cmd, req, m, waitMs)`, D17) and, for a v3 client whose request **would have to
enqueue**, runs `Preflight.run(cmd, req)` before it queues: missing or ill-typed fields, unknown
`op` kinds, bad `lane`/`isolation`/`purpose`/`verify`, `expect` types. `Preflight` is a registry
(D31): E3a registers the generic checks under the key `*`, E2 registers `fork_project`'s
(`purpose`, `verify`) from `ForkCommands`, E4 registers `script`'s (`lane`, `isolation`) from
`ScriptCommands`, each by **extracting** the command's own validation into one method used by the
command and by the preflight (so the two cannot drift). A request admitted at once keeps today's
order of errors, and a v2 request is never preflighted, so no existing golden changes.

**Import wait fix (all protocols, declared v2-visible, 5.1).** `ImportCommands` waits for the import
gate without a deadline, then calls `scheduler.admit(c, "import", m, waitMs(req))` and
`lockProject(p, false, waitMs(req), "import")` (`ImportCommands.java:112-114`) with `waitMs`
defaulting to 10 s (`Requests.java:30`): an import that waited an hour for its turn can fail `busy`
ten seconds after reaching the front. Both calls take the remaining wait computed from
`limited`/`deadline` (`:79-81`), unlimited when unlimited. **This moves a v2 outcome in both
directions, and both are declared (V2, 5.1):** (1) a v2 import **without** a `wait` field, which
waits unlimited in the gate, now also waits unlimited for the slot and the project lock instead of
failing `busy` after 10 s (a failure becomes a success); (2) a v2 import with an **explicit numeric**
`wait` that spent most of it in the gate now fails `busy` at the end of that one budget, where today
its slot and lock waits each got a fresh full `wait` and it could succeed (a success can become a
failure; the total is now what the caller asked for). The goldens cannot see either, so the tests
`import_wait` (no `wait`) and `import_wait_explicit` (a numeric `wait` spent in the gate) run on a v2
connection.

**Cancel-aware lock waits (one timed `tryLock`, cancel by interrupting the waiting thread).**
`Caller.enter(c, id)` (`Caller.java:86`, called from `Connection.respond`) also stores the request's
`RequestMonitor`; `Caller.monitor()` returns it. The three locks a request waits on are **fair**
`ReentrantReadWriteLock`s (`ProgramEntry.java:115`, `ProjectEntry.java:43`, `Overlay.java:54`), and
today each of those waits is **one** timed `tryLock(wait)` (`ProgramEntry.java:195`,
`Access.java:109`, `OverlayCommands.java:142`). **These three request-bound timed waits are what this
section converts, and the claim stops there.** The overlay lifecycle also takes **untimed,
uncancellable** `lock()` calls (`OverlayCommands.java:228`, `:238`, `:251` in `openOverlay`, `:319`
in `rebuildOverlays`, `:352` in `dropOverlays`, which also runs from the cleanup path, and `:404` in
`promoteOverlay`, which this design moves to the `maint` lane). They are **out of scope** of E3b: a
request blocked there ignores `cancel`, the deadline and the dead-client release exactly as today
(they are short, overlay-local critical sections, and an overlay is not the shared program), the
limit is listed in section 6, and E3b's `abandoned_holder` test does not cover them. Converting
them to `Waits.tryLock` is a later, separate decision (it needs a lock-order review of
`promoteOverlay`). The timed `tryLock(long, TimeUnit)` honours the fair policy: the thread
joins the lock's FIFO queue once and keeps its place for the whole wait, and while an exclusive
locker is queued no later reader gets in ahead of it. Two obvious ways to make the wait cancellable
break that, and both are **rejected**:

- *Polling in 100 ms slices of a timed `tryLock`*: when a slice times out the thread's queue node is
  cancelled and removed (AQS), and the next slice enqueues a **new node at the tail**. An exclusive
  locker (a `save`, a `refresh`, an exclusive script, maintenance work) would lose its place every
  100 ms and wait behind every reader that arrived meanwhile, so steady readers could starve it.
- *Polling the untimed `tryLock()`*: it is documented to **barge** (it takes a free lock whether or
  not threads are queued, even on a fair lock), so a poller never queues and a reader's poll
  overtakes a queued writer.

The design keeps today's single wait and delivers cancel from outside. A new static
`Waits.tryLock(Lock, waitMs)` (E3b; same call shape, so no signature changes) does one
`l.tryLock(waitMs, MILLISECONDS)` on the request's own thread, so queue position and fairness are
exactly today's, with a small registration state machine on the request's `RequestMonitor`
(`IDLE`, `WAITING`; all transitions under one mutex):

1. *Enter.* Under the mutex: if the monitor is already cancelled, throw `cancelled` without
   touching the lock; else record `thread = currentThread` and set `WAITING`.
2. *Wait.* `l.tryLock(waitMs, MILLISECONDS)`. Nothing polls and nothing slices; `client.leaving`
   needs no check of its own, because `Connection.run` sets it and then cancels every running
   monitor (`Connection.java:95-97`), which takes the path below.
3. *Cancel.* `RequestMonitor.cancel()` (overridden; it is what `Session.cancel`, `Connection.run` and
   the deadline timer already call, `Session.java:393,409`, `RequestMonitor.java:118-121`) sets the
   flag as before and then, under the mutex, **if the state is `WAITING`, sets `interruptSent` and
   interrupts the registered thread**. In any other state it only sets the flag. An interrupt is
   therefore sent only while the thread is inside this wait and can never reach later work: an
   interrupt that lands in Ghidra's database I/O can close a channel (`ClosedByInterruptException`),
   which is the hazard this ordering prevents.
4. *Leave.* In a `finally`, under the same mutex: set `IDLE`, read and clear `interruptSent`, and if
   it was set clear the thread's own interrupt flag (`Thread.interrupted()`) **before anything else
   runs on the thread**; an interrupt that arrived after `tryLock` returned but before this step
   is cleared here too. An interrupt that was **not** ours (`shutdownNow()` in `Connection.run`)
   leaves the flag set, as `ProgramEntry.java:197-200` does today.
5. *Outcome.* Lock obtained and `interruptSent` or the monitor cancelled: `unlock()` it and throw
   `cancelled` (a lock acquired while a cancel raced is never held across the error). Not obtained
   and `interruptSent`: `cancelled`. Not obtained by timeout: today's `busy`, with `reason` and
   holder detail. A monitor-less caller (the cleanup waits) gets the plain timed `tryLock`.

The request-bound waits it replaces are `Access.lockProject` (`Access.java:109`),
`ProgramEntry.acquire` (`ProgramEntry.java:195`) and the overlay lock (`OverlayCommands.java:142`).
The scheduler slot wait is not an AQS lock: it already waits on its own condition in 100 ms
steps and checks the monitor (`Scheduler.java:157-183`), keeps its own FIFO per key, and is
unchanged. A `timeout` deadline that fires during a lock wait now ends that wait too (today the
timer cancels a monitor nobody on that wait reads). The cleanup waits (`CLEANUP_WAIT_MS`:
`ProgramCommands.java:622`, `ProjectCommands.java:408`) are not request-bound and are handled by
the dead-client rule below.

*Tests (E3b, all on a protocol-2 and a protocol-3 connection).* `writer_vs_steady_readers`: eight
readers loop (each holding the shared lock about 50 ms, arriving so that the lock is never free for
long) and one exclusive request (an exclusive script) arrives: it must acquire within the longest
reader hold times the readers already queued ahead of it plus a margin, and every reader that
arrived **after** it must start after it (ordering read from the request timestamps), so the writer
is not starved and the FIFO is preserved; before the implementation exists the same test is run
against a build that polls in slices, and the run must fail (the premise check of the E0
convention), the result recorded. `cancel_while_waiting`: a request queued behind an exclusive
holder is cancelled by id and answers `cancelled` within 1 s, the requests queued behind it keep
their order and run when the holder ends, the holder is unaffected; 200 iterations of a cancel
sent at the instant the holder releases end only in `cancelled` or success, never a leaked lock
(`status.programs[]` shows no reader or writer afterwards) and never a stray interrupt (a `save`
and a decompile on the same connection afterwards succeed, and the daemon log has no
`ClosedByInterruptException`). `deadline_in_lock_wait`: a request with `timeout` shorter than its
lock wait answers `cancelled` at the deadline.

**Lock-queue cap (opt-in, v3).** For a v3 request that carries `lane:"quick"`, at most
`max(2, slots/2)` may wait on one program's lock (`ProgramEntry.waiters`); further ones get `busy`
at once with `reason:"lock_queue_full"` and a `retryAfterMs`. The wait then happens in the client
(Hydralysis already treats `busy` as retryable and has its own budget), not in an engine slot.
Parking a waiter's slot is **not** attempted: it breaks "lock holders never wait for a slot"
(`Scheduler.java:42-43`), which is what makes slot-then-lock deadlock-free, and it needs a written
lock order and a stress test of its own.

**Dead clients: bounded release (all protocols, declared v2-visible, 5.1).** It changes how long
*other* clients wait for a dead one, not any reply shape. `Connection.run` (`Connection.java:93-108`) cancels the
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
- other requests for that program get `busy` immediately instead of a silent wait, with
  `holder`/`holderInfo` saying "abandoned request <cmd>, client gone, running N s" (the existing
  `busy` keys, so a v2 client reads it unchanged) and, for v3 only, `details.reason:"abandoned"`;
- `status.programs[].abandonedRequests[]` and `health.abandoned[]` list it;
- **the program object is not disposed** while the abandoned thread runs (`Session.reap` already
  uses non-blocking `tryLock`, `Session.java:194-199`, so it cannot).

What this cannot do: Java cannot kill a thread that ignores cancel and interrupt, and cannot
unlock a `ReentrantReadWriteLock` held by another thread. A non-cooperative script keeps its
program lock after its client is gone; the design bounds the wait, makes the state visible and
keeps everything else running. The only hard remedy is a helper JVM for user scripts, which is out
of scope and said so in the README. `RusticQuery` calls `monitor.checkCancelled()` at 17 sites
(`RusticQuery.java:126, 254, ...`); new loops must call it.

A client that ends a stalled call by half-closing its connection (the hydra.2/3 deadline of 7.6) is
such a dead client from the engine's side: on hydra.3 it is released only when its requests end
(measured in 7.6, because `Connection.run` waits in `awaitTermination(1, HOURS)`), on hydra.4 by this
rule after about `cleanupGraceS + abandonWaitS`.

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
cost is the README figure for an unedited overlay (two README rows, not one: 26 ms and +3 MB on the
174-function project, `README.md:410`; 116 ms and +54 MB on the 243,855-function benchmark program,
`README.md:409`) and is *unmeasured on KotOR*: `private` becomes the Hydralysis default for `ghidra_run` only
after that measurement (7.4). Reply adds `"basedOn":{"saved":true,"programRevision":"..."}` and
`"unsavedIgnored":0`.

A spike in E4 tests whether `Program.lock(reason)` on the shared program turns a mutation attempt
into an exception without disturbing concurrent readers. If it does, `shared` gains enforcement;
if not, the guarantee for `shared` stays "rolled back, measured, and RusticQuery is source-controlled
and hash-pinned", and the README says so. A script is still Java with the daemon's rights: this
is containment of the current program, not a sandbox (`ScriptCommands.java:67`).

### 3.7 Daemon configuration

New keys, in `<state>/config.json` and as command-line flags (`HeadlessSession.java:64-86`,
`README.md:121-150`). All have safe defaults. Today every key needs an edit to `HeadlessSession`'s
option parser and to the launcher, so five packages would collide on both files. E1 therefore adds
one generic route and no package adds a flag of its own: the launcher (P1a) passes every entry of
a new `engine` object in `config.json` to the JVM as repeatable `-set key=value` flags, the parser
(E1) stores them in `Settings.java`, and each package reads its own keys in its own classes
(`Settings.integer("maintSlots", 2)`). The table lists the keys and their owners; R1 documents
them in the README. No new environment variable is added.

| Key | Default | Meaning | Read by |
|---|---|---|---|
| `maintSlots` | 2 | maint lane slots | E3a |
| `quickScriptMaxS` | 60 (hard max 120) | longest `timeout` for `lane:"quick"` scripts | E3a (the lane decision) |
| `maxRunningPerKey` | quick `max(1,slots/2)`, long `max(1,slots-1)`, maint 1 | work-conserving per-key cap | E3a |
| `cleanupGraceS` / `abandonWaitS` | 15 / 5 | dead-client release | E3b |
| `requireExpect` | false | shared-writer edits need `expect` | E1 |
| `requireBackupForUpgrade` | true | the upgrade gate | E2 |
| `orphanKeepS` | 0 (never) | orphan dump and discard | E3b |
| `watchdogStallMs` / `starveMs` | 15000 / 30000 | `health` thresholds | E5 |

`-Dghidra.session.testHooks=true` is not a config key: a launch property only.

### 3.8 Launcher (`support/ghidra_session.py`, P1a and P1b)

- **P1a.** `PROTOCOL = 3`, new `PROTOCOL_MIN = 2`; the hello sends `protocol=3`; `check_compatible`
  accepts a reply in `[PROTOCOL_MIN, PROTOCOL]` and exposes `session.protocol`; the endpoint check
  accepts any overlap of `[2,3]` with `[protocolMin, protocolMax]` (absent: the single `protocol`).
- **P1b.** `SocketSession.call(cmd, deadline=None)`: replaces `sock.settimeout(None)`
  (`ghidra_session.py:845`) for the wait on that reply; on expiry sends `cancel target=<id>` and
  raises `SessionError("deadline_exceeded")`; the connection stays usable (the library owns its
  reader, so its own `wait` can be timed and no thread is ever left blocked in `readline`). This exists only in the
  1.1.0 library that ships with hydra.4: the hydra.2/3 install ships 1.0.0, whose `call` waits
  without a limit, and Hydralysis loads the session module **from the engine install**
  (`hydra.py:48` `SESSION_MODULE`, `:229-233` `Engine.module()` and its use in `_connect`), so against a hydra.2/3 engine it cannot
  use P1b and runs the deadline helper of 7.6 instead (half-close and abandon, tested there; **not**
  `session.close()`, which hangs on 1.0.0). Structured
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
   canonical body (the canonical form of 3.4, Python-only here, so floats are allowed). A reader that finds a zero-length, unparseable or mis-sealed file falls back to
   `<file>.bak` (the previous sealed version, kept by the writer) and, failing that, raises
   `store_corrupt` with both paths. It **never starts empty** (today `load_store` raises on a
   bad file but treats a missing one as "no edits", `workcopy.py:50-58`).
3. `AppendLog` for CRC-framed JSON lines (used by `CURRENT.log`, intent logs, the backup log).
   **Checksum: CRC-32 (IEEE 802.3) as `zlib.crc32` from the standard library**, written as 8
   lower-case hex digits. Hydralysis depends only on `pefile` and `capstone` (`pyproject.toml:9-12`)
   and Python's stdlib has no CRC-32C, so CRC-32C would need a new dependency or a pure-Python
   table; CRC-32 detects torn and garbled lines, which is all it is for (it is not a defence against
   tampering). A **line** is `crc-hex8 SP json LF`. A line is **valid** only if it is complete (ends
   in LF), its CRC matches its JSON bytes and the JSON parses; a final fragment without LF is never
   valid, even if its CRC happens to match, because no append is acknowledged before its LF is on
   disk. Each append is written with `O_APPEND`, then `os.fsync`.

   *Readers* (read-only, hold no lock, never write: the doctor is one) take the longest prefix of
   valid lines. An invalid **suffix** (one or more invalid lines or an unterminated fragment, with
   no valid line after it) is a **torn tail**: it is ignored, not an error, and is reported
   (`torn_tail:{offset, bytes}` in `status` and the doctor). An invalid line **followed by a valid
   one** is corruption (4.4).

   *Writers* repair before they append, **on every acquisition of the log's writer lock** (the
   rule that was missing: without it the next append lands after a fragment that has no LF, merges
   into one line, fails its CRC and the commit point is lost, while starting a fresh line instead
   would make the fragment an invalid line before a valid one, which the reader rule calls
   corruption). The trigger is **not** "the first append in a process": a long-lived writer process
   (an MCP process doing `commit_revert`, a rollback, a `recover` or `backups.log` appends) has long
   since made its first append, and if a second process is killed in the middle of an append after
   the first released the lock, the long-lived process takes the lock again, would not rescan and
   would append after the unterminated fragment, losing the commit point exactly as above. Only
   the commit job (a new worker process per commit, 4.6) would be safe by accident. So, under the
   log's writer lock (`.commit.lock` for `CURRENT.log` and the intent logs, the log's own `.lock`
   for `backups.log`), on **every acquisition**, the writer first makes the **cheap check**: the
   file ends in LF **and** its size equals the end of the last valid line it knows (the end it
   verified, or wrote itself, at its previous acquisition in this process; nothing remembered
   means a scan from the start; a failed append forgets what was remembered). Unchanged and clean:
   append. Otherwise (another process appended, or the last byte is not LF): (a) scan from the last
   known valid end (from the start when none is known); (b) on corruption (an invalid line before
   a valid one) refuse with `lineage_corrupt` and append nothing; (c) on a torn tail first copy the
   tail bytes to `<log>.torn-<offset>-<sha8>` and force that copy, then truncate the log to the
   end of its last valid line and force it, then append one line to `<log>.repairs` (`{at, offset,
   bytes, sha256, by}`; best effort, its loss costs only the record of the repair); (d) append its
   own line. The check costs a `stat` and one byte when nothing changed, and the bytes another
   process added otherwise. Every step is idempotent, so a crash inside the repair is repaired by
   the next writer. The tail is never part of a hash chain (`prevHash` is the hash of the previous
   **valid** line). Truncating loses nothing acknowledged, because only a fully written, fsynced
   line is ever acknowledged.

   *Reading budget.* The Y0a code of `589432e` reads a whole log through `localio.read_bytes`
   (`durable.py`, `AppendLog.scan`, `repair`, `last`), which has a hard 32 MiB budget
   (`localio.DEFAULT_MAX_BYTES`): a `CURRENT.log` or `backups.log` past 32 MiB would make every
   reader and every writer raise `ValueError`, and every read is O(n). Required: logs are read by
   streaming (no `localio` budget), a reader needs only the tail window (the last valid line) and
   a full scan runs only where the whole log matters (the lineage open, `verify`, the doctor), with a
   rotation or checkpoint policy owned by Y2 (`lineage.py` is its file; until it exists a log of
   that size is a recorded limit, section 6). The removal of the `localio` read from `AppendLog` is
   owned by Y0e (8.2), because `durable.py` is Y0a's file and Y0a is closed.

   *Tests* (`tests/test_durable.py`): for every byte offset of the last line of a log, cut the file
   there, read (the valid prefix, `torn_tail` reported, no error), append (the repair is recorded, the
   copy exists, the log is clean) and read again (the prefix plus the new line, never
   `lineage_corrupt`); a mid-log invalid line followed by a valid one is refused by the writer and
   by the reader; a crash injected inside the repair (`durable.fault`) heals on the next append;
   a log larger than 32 MiB is appended to and read without error. **Two-process test (the
   trigger):** process A appends a line and releases the lock **and stays alive**; process B appends
   through a fault (`torn:<n>`, for `n` at 1, mid-line and every byte but the LF) and is killed
   mid-line; process A appends again: a `.repairs` record and a `.torn-*` copy exist, the log is
   clean and holds A's two lines and no fragment, and **no `lineage_corrupt`** is raised by A or by a
   reader. The same test with a rollback append (`reason:"rollback"`) and a `backups.log` append.
   The commit-level test is `publish_torn` followed by a successful new commit (4.6).
4. Routed through `durable`: `workcopy._save_store`, `backends.write_json` (and so `targets.register`,
   `working/state.json`, job records in `overlayjobs`), and every new file of 4.4-4.6. A write gate in the
   test suite (Y0a's AST gate, `tests/test_durable.py`) fails when a new `write_text`, `write_bytes` or
   `replace` of a record appears outside `durable`; the sites it freezes today, and who moves them, are
   in 8.2.
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
  "commits": [{"cid": "c-71ab", "generation": 2, "snapshot": 38, "ids": ["e1...", "e7...", "e9..."],
               "skipped": [{"id": "e4...", "reason": "drift", "subject": "address:0x402000", "field": "name"}],
               "ids_sha256": "...", "bundle_sha256": "...", "at": 1793100500.0, "reverted": false}],
  "archived": [],
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
- **Commit state is a committed-id set, not a watermark (D32).** There is no `committed_through`
  number: a record is **committed** iff its `id` is in the `ids` of a commit entry whose `reverted`
  is false, and **pending** otherwise. A single watermark (`seq > N` is pending) cannot represent
  a commit that takes a subset (`only`) or that leaves a drifted record pending (`on_drift:"skip"`),
  because a pending record can sit below a committed one: it would be taken for committed and never
  replayed. The entry's fields: `ids` (committed, authoritative), `skipped` (selected but left
  pending, with the reason; informational, never read to decide state), `snapshot` (the store revision
  `upTo` at step 1; informational), `ids_sha256` (over the sorted `ids`), `reverted`. At most one
  commit entry exists per `cid`.
- **Replay set.** The working copy replays `pending`: the edits that are not committed, **in `seq`
  order**, onto a base that already contains the committed ones. The program's `overlay_state` marker
  (`RusticQuery.java:2300-2339`; `workcopy.state_of`, `:83-91`) is extended from
  `{revision, edits, ids_sha256}` to also carry `base:{lineage, generation}` and `committed_sha256`
  (the sha256 of the sorted committed ids), and `_prefix_matches` (`workcopy.py:341-349`) compares the
  marker's ids against the **pending** list and requires `base` and `committed_sha256` to match. A
  program built before a commit therefore never matches after it, and a v2-style marker (no `base`)
  matches only generation 0 with an empty committed set. Without this a commit would be applied
  twice. `state_of` reading `store["edits"]` becomes `pending_of(store)`.
- **What a subset or skipping commit does, exactly.** The unit is the **record** (one edit with all
  its effects): it is committed whole or stays pending whole. A selection `only:{ids, authors}` names
  the records `S`. A record depends on every earlier pending record that shares a coarse subject with
  it (the strings of `revisions.subjects_of`; a record with subject `*`, a bulk import, shares one
  with every other); `S` must be closed under that relation, else the commit refuses
  `selection_not_closed` with the missing ids, or adds them when `include_dependencies:true`. The
  records are applied in `seq` order. **A `batch` is selected whole or not at all**: an `only` that
  names some records of a batch (or an author who owns only part of one) selects the rest of it too
  through the closure (`selection_not_closed` names them, or `include_dependencies:true` adds
  them), because `revert` already treats a batch as one unit and a commit must not split what a
  revert cannot. With `on_drift:"skip"`, a record whose first effect on a
  `(subject, field)` no longer matches the master (4.6 step 5) is skipped **together with every
  later record of `S` that depends on it**; the rest of `S` is committed. The commit entry then holds
  `ids` = the committed records and `skipped` = the rest of `S`; records outside `S` are simply
  not in `ids`. Skipped and unselected records stay pending, keep their `seq` and their place in
  the replay order, and are replayed onto the new generation; their `before` values are checked
  again at the commit that takes them. **Invariant:** for any coarse subject, the committed
  records are a prefix, in `seq` order, of that subject's non-reverted records. Only the dependency
  closure and skip propagation can keep it true, and it is what makes replaying a pending record
  after a committed record with a later `seq` safe (they never share a subject). **The invariant is
  per coarse subject, not semantic.** A subject is an address, a type path or `structure:functions`
  (`revisions.subjects_of`), so a subset commit can ship a `signature` or `data_type` edit (subject
  `address:...`) without the pending `struct` edit it uses (subject `type:...` or
  `structure:functions`); the closure cannot see that (section 6 already said a rebase cannot).
  What happens is not assumed but tested (Y2, `subset_missing_type`): applying the signature in the
  candidate must **fail closed**, i.e. `apply_overlays` rolls the whole transaction back and the
  commit ends `ABORTED` with the effect named, and nothing is published. If the engine instead
  accepts the signature and quietly substitutes an undefined type, the test fails and the closure
  must be extended with type references (a `uses` list recorded in `effects`) before subset commits
  ship; until then `only` is documented as "no semantic dependency tracking".
- **`revert` of records.** `revert` of a record whose id is in a live commit's `ids` is refused
  (`already_committed`); undo it with a new inverse edit or `commit_revert`. `revert` of a
  **pending** record removes it from `edits[]` and accepts a record id or a `batch` id
  (`workcopy.py:569-591`). Removing an earlier record leaves a later pending record on the same
  `(subject, field)` with a stale `before` (it equals the removed record's `after`): the step 5
  chain check and `verify_before` of 4.6 would flag it as drifted against the master, and with no
  `overwrite` the owner could not commit it. **Rule: a `revert` that would leave such a record is
  refused with `has_dependents` and the ids of the later records; `cascade:true` reverts the named
  records and every later pending record of the same `(subject, field)` (a batch always goes
  whole).** Recomputing the `before` chain is rejected: a recomputed `before` is no longer the value
  the analyst saw when the edit was made. Test (Y1): the earlier record of a chain is refused with
  its dependents named; `cascade` removes the chain; the last record of a chain reverts freely;
  reverting by `batch` id removes the batch.
- **Compaction (policy; the caps are real).** `MAX_OVERLAYS = 4096` (`analysis.py:26`) is checked on
  every `edit()` (`workcopy.py:~547`) and the 20 MiB `MAX_HISTORY_BYTES` on every load and save
  (`workcopy.py:54,74`); `effects` with `before` and `after` make a record larger than today's.
  Committed records are history, not state, so they are **archived, never deleted**: when a commit
  reaches `FINALIZED`, the records of the **previous** live commit are moved out of `edits[]` into
  `overlays/archive/<store key>/<cid>.records.json` (a sealed file written through `durable` before the store
  rewrite that drops them), and the store keeps only that commit's entry reduced to `{cid, generation,
  count, ids_sha256, archive}` under `archived[]`. The latest commit's records stay in the store,
  because `commit_revert` needs them (a revert makes them pending again). Rebase and bundle export read
  an archive on demand; the committed ids needed by other views' rebase come from the generation
  manifests (4.4), which list them. A reverted entry is kept as history (its ids are pending) and archiving skips it. **`commit_revert`
and the archive:** after the latest commit c2 is reverted, the latest *live* commit is c1 again, but
c1's records were archived when c2 finalised, so they are **not** in `edits[]`. `commit_revert` of
c1 therefore **rehydrates**: it reads `overlays/archive/<store key>/<cid>.records.json`, verifies the
file's seal and its `ids_sha256` against the entry, and in the same atomic store write moves the
records back into `edits[]` (as pending, in `seq` order), drops c1's `archived[]` entry and marks
the commit entry `reverted:true`; if the rehydrated records would exceed the 4096-record or
20 MiB caps the revert is refused with `store_full` and nothing changes (the owner commits or
exports first). A missing or mis-sealed archive refuses with `archive_unreadable`. The statement
"the records are still in the store" holds only for the *latest* commit; for an earlier one the
archive is the source. Test (Y2, `revert_chain`): commit c1, commit c2, revert c2 then c1: the
records of both are pending again, in `seq` order, and the generation pointer is back at 0. After this the 4096 and 20 MiB limits bound the **live**
  records (pending plus the latest commit's), not the history. A store with more than 4096 pending
  records still cannot take another edit: commit it (a subset commit is allowed), or export a bundle
  (section 6).

**Journal = recovery = commit source, stated once.** The store is written, sealed and fsynced
inside `.sync.lock` **before** `edit()` returns (`workcopy.py:543-554`). So (1) an acknowledged edit
is in the record; (2) the only crash window is "applied to the working copy but not yet stored",
which is self-healing: the program's marker then claims more records than the store has,
`_prefix_matches` returns `None` (`workcopy.py:341-349`) and the next sync rebuilds from the store;
(3) the commit reads the same record set. There is no second log. The edit's lifecycle: `proposed`
(request) -> `applied` (working copy, in the daemon) -> `recorded` (sealed store; the acknowledgement)
-> `committed` (its id is in a live commit's `ids`) -> `archived` (a later commit finalised) ->
`superseded` (a later generation changed the subject).

### 4.3 Idempotency in the client (Y0b)

`hydra.Engine.call` retries **every** command once after `closed` (`hydra.py:268-287`). That is
correct for reads and wrong for a mutating call whose reply was lost. Rules: reads, opens, `status`,
`hello` and `script` with a read action are retried; `script apply_overlays`, `save`, `import`,
`fork_project`, `edit`, `rename`, `comment` are **not**: they raise `EngineError` with
`code:"closed"`, `details.ambiguous:true`, and the caller reconciles (`_sync` re-reads the marker;
`fork_project` checks whether the destination appeared). Hydralysis edits are identified by their
`id`; a commit by its `cid`. What Y0b shipped beyond that list, recorded as decided: `close_project`,
`refresh`, `switch` and `reopen` are also retried (a repeat of a close that landed answers `not_found`,
which the caller reads as done); a lost `apply_overlays` reply now fails the **current** sync with
`details.ambiguous` and the **next** sync self-heals from the marker (where the old blind re-send hid
it); a mutating call on a connection that died before it was sent is reported ambiguous too
(conservative: a cheap `ping` before the call would reduce false ambiguity, optional, not required);
user scripts (`userscripts.py`) and `RusticSetup.java` are not re-sent after a drop, since 4.3 allows
only a read action of `script`.

### 4.4 Lineage and generations (Y2)

Layout, under the Hydralysis root (not beside the project: adoption never writes the project
folder; the root is on the owner's Dev Drive so forks are block clones, and `generations_root` can
override it, with a doctor warning when it is not the volume of the current generation):

```
<root>/lineages/<lineage id>/
    lineage.json                {format, id, origin_key, origin_gpr, program, sha256, createdAt}
    CURRENT.log                 append-only, CRC'd lines (+ .repairs, .torn-* after a tail repair, 4.1)
    commits/<cid>.intent.log    CRC'd lines (4.6), one log per cid, lines carry an `attempt` number
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

- **Torn tail** (an invalid suffix with no valid line after it, 4.1 item 3): a **reader** ignores it
  and reports it in `status` and the doctor; it never repairs and never raises. It can only show an
  older, consistent state, because a line is forced before any acknowledgement or later step. The
  **next writer** repairs it first, **on every acquisition of** `.commit.lock`, before any append (4.1 item 3: not only on a process's first append): it preserves the
  fragment as `CURRENT.log.torn-<offset>-<sha8>`, truncates the log to its last valid line and
  records the repair in `CURRENT.log.repairs` (the same rule applies to the intent logs and
  `backups.log`). So a crash in the middle of the commit-point append is followed by a normal,
  successful new commit, not by a lost line or a false `lineage_corrupt`. A long-lived writer process
  is covered by the same rule: the two-process test of 4.1 is part of the Y2 fault matrix.
- **Mid-log gap** (an invalid line with valid lines after it): `lineage_corrupt`. Reads resolve to
  the last good line before the gap with the error shown on every `status`; commits and reverts are
  refused until the owner repairs it. Silent repair of a mid-log gap is not done; the torn-tail
  repair above is the only automatic one, and it is recorded.
- `MANIFEST.json` in a generation folder: `{format, cid, base:{generation, revision}, engine,
  dbVersions, files:[{path,size,sha256}], filesetSha256, backups:[manifest sha256...], store:{view,
  revision, snapshot, ids:[committed record ids], skipped:[ids], ids_sha256, bundle_sha256}, selfSha256}`
  (the ids make the manifest the durable source for step 9 and for other views' rebase). **A generation folder is invisible until its manifest
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
  machine rule is ask before creating anything over 50 GB). That threshold is **per backup**, so many
  below-threshold backups add up unbounded. The confirmation text and the doctor therefore always
  state the **cumulative** cost: the sum of the sizes of the lineage's verified backups under each
  root (from `backups.log`) plus this one, the free space of the root's volume, and, for a clone, the
  caveat that its logical size overstates the physical blocks it adds. `backup_root_warn_gb`
  (default 200) makes the doctor warn when a root's cumulative logical size passes it; no backup
  is deleted automatically (D28).
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
- On hydra.2/3 (no `purpose`, no `open`): `fork_project` into the backup folder with **`writable:false`**
  (the field defaults to true, `ForkCommands.java:82`, and a writable registration would hold the
  backup open for writing), then `close_project`; the fork's sidecar is that of any fork. Python
  hashes the files and writes `backup.json` with `writer:"hydralysis"`; if the hash check fails it
  writes no manifest (the folder stays invisible, 3.4).

### 4.6 Commit as a new generation (Y2)

A commit is a Hydralysis job of kind `commit` (`overlayjobs`/`jobowner`: a worker process, so it
survives the MCP process). Request: `ghidra_query action=type_edit options.kind=commit`.

```json
{"kind":"commit","expect_revision":41,"confirm_one_way_upgrade":true,"on_drift":"refuse",
 "only":{"ids":null,"authors":null},"include_dependencies":false,"dry_run":false,"backup":"auto"}
```

`only` null means every pending record. A non-null `only` selects a subset and `on_drift:"skip"`
leaves drifted records pending; what both do to the store is fixed in 4.2 (committed-id set,
dependency closure, skip propagation).

Preconditions (checked first, in order; any failure creates nothing): `expect_revision` equals the
store revision; `base.master_revision` equals the current generation's revision, else `master_drifted`
(rebase first, 4.7); a non-empty effective record set; no `before_unknown` records unless
`allow_unverified_before`; `confirm_one_way_upgrade:true` whenever `open_project.format.upgradeRequired`
is true **or unknown** (always the case on hydra.2/3, which has no `format`); `.commit.lock` and
`.sync.lock` held briefly to snapshot `upTo = store.revision` and the reference texts of step 1.
`dry_run` runs the preconditions, the selection closure and the drift pre-pass of step 5 against a
read-only probe of the current generation and returns the plan (the `ids` it would commit, `skipped`,
`excluded` functions, the cumulative backup cost); it has no side effects (tree-hash tested).

The confirmation text names what is lost: after the commit only engines at program DB version >= the
engine's can open the generation. Versions are read from `analysisIdentity.dbVersions`; for the other
Ghidra releases the client uses the repository's `format-matrix.json` (E2), which at this commit
records what `README.md:1003-1004` states (program database 33 on main and 32 in 12.1.4; data type
database 3 and 2) and is checked by the DB-version gate.

Steps. Each step is preceded by a forced line in `commits/<cid>.intent.log`:

1. `PREPARE` - preconditions above, then, still under `.sync.lock` (the only moment edits are held
   up, bounded by `snapshot_budget_s`, default 20, after which the sample shrinks): record `upTo`, the
   selected set `S` after the dependency closure of 4.2 and its `ids_sha256`; and capture the
   **reference**: the decompile text, taken from the working copy at `upTo` (the working copy is
   in sync with the store here, and its `overlay_state` marker is written to the intent log as the
   proof), of the sampled functions (default cap 25 per effect kind) touched by `S`. The reference
   is a **snapshot at `upTo`**, not the live working copy, which keeps changing while steps 2-7 run.
   A function whose subject also appears in a pending record outside `S` is excluded from the
   comparison of step 7 (reported as `excluded`), because the working copy differs from the
   candidate there by design.
2. `BACKUP_DONE {backup, manifestSha256}` - a fresh backup of the **current generation** per policy,
   re-hashed. A failed primary aborts. A failed secondary aborts or warns per `backup_min_verified`.
3. `CANDIDATE_RESERVED {gen}` - the generation number is reserved in the log **before** the folder
   exists, so a crash cannot reuse a number for a different candidate.
4. Fork: `fork_project(project=<current generation>, path=gen/000N, purpose:"generation")`; open the
   candidate writable owned by the job only, `open_program writable:true upgrade:true backup:<manifest>`
   (the gate passes because the backup is of this revision; D12/D13). The candidate is never shared.
   On hydra.2/3, which has no `purpose`, the job rewrites the new fork's sidecar to
   `disposable:false, purpose:"generation"` through `durable` right after the fork, so that a later
   hydra.4 engine does not take the generation for a disposable fork (D12); this happens before
   step 7 hashes the folder.
5. `APPLIED {ids_sha256, n, skipped[]}` - first a **drift pre-pass**, read-only on the opened candidate
   (nothing written yet): for the first effect of each `(subject, field)` among `S` in `seq` order,
   `annotation_probe` compares its `before` with the live value; every later effect on the same
   `(subject, field)` is chain-checked offline (its `before` must equal the previous effect's
   `after`). A record with any mismatch is **drifted**. `on_drift`: `refuse` (default) returns the
   full list and publishes nothing; `skip` removes each drifted record and every later record of
   `S` that depends on it (4.2) from the set, leaving them pending, and commits the rest (`C`, the
   ids that go into the commit entry; `skipped[]` is the removed list with reasons). There is no
   `overwrite`. Then, inside **one transaction**, run RusticQuery `apply_overlays` on `C` with
   `verify_before:true`: every effect's `before` is compared with the live value again before it is
   written, as the authoritative check (nothing else writes the candidate, so a mismatch here after
   a clean pre-pass is a defect): it rolls the whole transaction back and names the effect, and the
   commit aborts. Write the program option `hydralysis_commit {cid, lineage, base_generation, snapshot,
   ids_sha256, bundle_sha256, engine}` (provenance inside the data) and **clear the
   `overlay_state` option** that `apply_overlays` writes into the program (`RusticQuery.java:2334-2335`):
   the candidate is a published generation, not a working copy, so it must carry exactly one
   marker, `hydralysis_commit`; a stale `overlay_state` would be read by any fork of the generation
   (`_marker`, `workcopy.py`) as a claim about records it does not hold. Y1 gives `apply_overlays` a
   `state:null` form for this, and Y2's base builder treats a non-empty `overlay_state` on a
   freshly forked generation base as stale and clears it (a second check that also covers a
   generation made some other way; the marker's `base` and `committed_sha256`, 4.2, make a leftover
   mismatch anyway). Then `save`, `close_project`.
6. `FILES_FORCED` - Python opens every candidate file and `os.fsync`s it (Ghidra's save does not promise
   an fsync; whether it does is **not verified**, so it is done unconditionally).
7. `MANIFEST` - hash every file, write `MANIFEST.json` (forced, write-through replace), then
   `VERIFIED` after: open a **clone** of the candidate read-only and check the program `sha256` equals the
   master's; function count and analysed flag equal; `annotation_probe` on every applied effect gives
   `after == actual` (same normaliser); the decompile of each sampled touched function (default cap 25
   per effect kind) succeeds and equals the **reference captured at `upTo` in step 1** (same engine,
   so identical), except the `excluded` functions; and a
   spot-check of 25 functions the commit did **not** touch decompiles identically to the previous
   generation (a regression guard for the engine upgrade). Any failure: `ABORTED`, the candidate is
   left unregistered for inspection, nothing else changes.
8. `PUBLISHED` - append the `CURRENT.log` line and fsync. **This is the commit point.**
9. `FINALIZED` - idempotent, keyed by `cid`, under `.sync.lock`, in **one atomic store write**: append
   the commit entry (`cid`, `generation`, `ids` and `skipped` read from the generation's
   `MANIFEST.json`, `snapshot`, hashes), set `base` to the new generation, archive the previous
   commit's records (4.2); then mark every other view's store stale (4.7); mirror to `targets.json`;
   release the locks. If an entry for this `cid` already exists the step does nothing.

Edits are **not** blocked during steps 2-7: records added meanwhile have `seq > upTo`, are in no
commit's `ids`, and so stay pending whatever their `seq`. Their `before` is the pre-commit state if
they touch a subject of `C` (the next commit's drift pre-pass reports that; it is not hidden), and
the post-commit state otherwise.

**Recovery table** (run when a lineage is opened and by `commit --resume`, under `.commit.lock`):

| Last durable intent | Observed | Action |
|---|---|---|
| none or `PREPARE` | no candidate folder | `ABORTED`, nothing to clean |
| `BACKUP_DONE` | a verified backup exists | keep it (it is never deleted), `ABORTED` |
| `CANDIDATE_RESERVED` ... `FILES_FORCED` | a partial or unverified `gen/000N` | invisible (no valid manifest); left in place, listed by `backups`; `ABORTED`; the client may resubmit with the same `cid` as a **new attempt** (the intent log's `attempt` number grows and a **new generation number** is reserved; the abandoned folder is never reused) |
| `VERIFIED`, no `CURRENT.log` line | a verified, unpublished candidate | left unpublished; a resubmission publishes it after re-hashing against its manifest (opt-in `resume_verified`, default false) |
| `PUBLISHED` written, `CURRENT.log` line torn or missing | the tail fails its CRC or has no LF | before the commit point: `ABORTED`. Readers ignore the torn tail and the **next writer repairs it** (4.1, on every acquisition of the lock: preserve the fragment, truncate to the last valid line, record the repair) before any append, so a resubmission as a new attempt appends a clean line; the verified but unpublished candidate stays unpublished (`resume_verified` applies as in the row above) |
| `CURRENT.log` line valid for this `cid` | `FINALIZED` missing | **roll forward**: re-hash the candidate against the manifest named in the line; equal: run step 9 (its ids come from that manifest, so the store ends in the same state whenever and however often this runs); not equal: append a `rollback` line to the previous generation (`reason:"candidate_failed_reverify"`), report |
| `FINALIZED` or `ABORTED` | | done |

`commit_abort` is honoured before step 8; after it the answer is `cancel_too_late`.

**Revert** (`options.kind=commit_revert`): only the latest **live** (not reverted) commit. Check the
previous generation's manifest still verifies; append a `rollback` line; the commit entry is marked
`reverted:true` and its `ids` become pending again (for the latest commit its records are still in
`edits[]`, because archiving leaves the latest commit's records in place; for the commit that becomes
the latest after an earlier revert they are **rehydrated from the sealed archive** in the same
atomic store write, or the revert is refused with `store_full` or `archive_unreadable`, all in 4.2)
and every view is marked stale. Restoring from a
backup is `fork_project` from the backup into a new generation folder, verified and registered the
same way; nothing touches an existing folder.

Fault points (`durable.fault`): `commit.after_prepare`, `after_backup`, `after_reserve`, `after_fork`,
`mid_apply`, `after_save`, `after_force`, `after_manifest`, `after_verify`, `before_publish`,
`publish_torn`, `after_publish`, `finalize_mid`. `publish_torn` writes the first `n` bytes of the
`CURRENT.log` line and exits (`torn:<n>`); the test then runs recovery and a **successful new
commit** with the same `cid` (a new attempt), for `n` at several offsets including 0, mid-line and
every byte but the LF, and asserts the repair record and the preserved fragment, one published line
for the `cid`, and O1-O6. Further faults: `intent_torn` (the same for an intent log) and a
subset-commit variant of `mid_apply` and `finalize_mid` (4.2: the skipped record is still pending and
is replayed, and is not taken for committed). The oracle after every fault run and recovery:
**O1** every file of generation 0 and of the previous generation is byte-identical (tree hash, excluding
`projectState` and lock files); **O2** every acknowledged store revision is present and the store's committed-id set agrees with the generations: the `ids` of each live commit entry equal the `store.ids` of that commit's published manifest (an archived entry is compared by `ids_sha256` with its archive file), no id is in two entries, and every skipped record is still pending, so nothing is committed twice or lost; **O3** `CURRENT.log`'s
last valid line names the old or the new generation and, if new, its manifest verifies and a read-only
open succeeds; **O4** no folder without a verifying manifest is offered anywhere; **O5** resubmitting the
same `cid` yields exactly one published `CURRENT.log` line and one commit entry; **O6** killing during recovery and recovering again reaches the
same state.

### 4.7 When the master generation changes

Other views (a named view forks from the master, not from `shared`; `workcopy.with_view`, `:36-43`):

| Thing | Behaviour |
|---|---|
| The committing view | The new commit entry's `ids` join the committed set; its working copy is rebuilt from the new generation's base, replaying only the pending records (those not in any live commit's `ids`, in `seq` order), including any the commit skipped or did not select. |
| Other views' stores | `stale: "master_generation_changed"` and `base` unchanged; reads keep answering from their working copy, labelled with the generation they came from; mutations are refused with `stale_view` until `rebase`. |
| `rebase` (`type_edit kind=rebase`) | Per record: drop it if it is already in the master, that is if its id (or, for a record that came from another view by publish or merge, its `merged_from` `{view, id}`) is in the `store.ids` of the manifest of a generation after this view's base (the committing view's store may be archived or another store, so the manifests are the source, 4.4); `converged` if the new master's value already equals its `after`; keep if a probe shows the master's value equals its `before`; otherwise list a conflict `{subject, field, before, master_now, after}`. The view's base binding moves only when the list is empty or resolved. The outcome is recorded in one atomic store write. |
| Working copies and bases | Keyed by `(lineage origin_key, generation, master revision, engine release)`; a different key means a different directory (`workcopy._base` keyed by master revision and engine release already, `:304-307`; the key adds the lineage and generation). **One** shared base per key across all views, so a new view costs one clone, one writable open and a replay. A replay that was running against the old base cannot be adopted (its marker names the old base: `base` and `committed_sha256`, 4.2). A base forked from a generation holds no `overlay_state` (commit step 5 cleared it; a non-empty one is treated as stale and cleared), so the first sync replays the whole pending list onto it. |
| In-flight exports | They snapshot at start; the header records `{lineage, generation, master_revision, engine release}` and resume is refused if any differ (`exporting.py:115-118` records the engine release and query key today). |
| Open programs of other clients | The old generation is immutable, so their reads stay consistent; they get the existing `refreshed`/`stale` marker through `Session.annotate` only if the registered path changes, which it does not for them. A client that wants the new generation reopens. |
| Runtime sessions and evidence | Not invalidated; provenance names the generation and a claim is flagged `superseded_by_generation` on read. |
| A GUI user saving a generation | `Revision.of` of a generation folder differs from its manifest: the lineage is flagged `tampered`, commits are refused until the owner re-adopts. (`projectState` is already excluded from `Revision`.) |
| The Ghidra GUI opening the original `.gpr` | Sees generation 0 with none of the committed annotations. This is a real regression against in-place commit; owner decision OD2. |

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
address, va, rva, kind, options, source, by, at, effects, committed}], bundle_sha256}`; the hash is over
the canonical JSON of 3.4 (sorted keys, minimal separators; Python-only here) without the hash field;
absolute paths and personal data are stripped; **no game-derived bytes are embedded**. `export_bundle`
is read-only (filter by id, author, revision range, and `state` = `pending`, `committed` or `all`;
it reads archived records on demand, 4.2). It exports each selected record whatever its commit state,
with `committed:true|false` as information only: it is not an input of import, and the committed-id set
is store state, not bundle content, so the store schema change of 4.2 leaves the bundle format as it
was. `import_bundle` is a dry run by default: it validates `bundle_sha256`, program `sha256`,
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
in the Hydralysis tree today; the source designs assumed it). **R1 owns the script** (writes and
tests it); Y4a only runs it to produce the pin bump and owns the files it edits. The release workflow gets a
`workflow_dispatch` dry run first (the hydra.2 release failed once before succeeding, per the critic).

**Matrix** (what "keeps working" means, exactly):

| Client | hydra.2/3 engine | hydra.4 engine |
|---|---|---|
| Any raw JSON-line client speaking protocol 2 | works | works; replies byte-identical (characterization at protocol 2); behaviour identical except the declared changes of 5.1 (V1 to V7, the first of which is the upgrade gate, 3.4) |
| stock `ghidra_session.py` 1.0.0 (protocol 2) | works | works at protocol 2 (endpoint says `protocol:2`) |
| `ghidra_session.py` 1.1.0 (protocol 2..3) | works at protocol 2, capabilities absent | full |
| Hydralysis 0.4.x | works (its own pin) | **refuses by its own pin** (`hydra.py:104-105`, `:246-249`) unless `hydra_allow_unpinned`; this cannot be fixed on the engine side and is stated, not hidden |
| Hydralysis 0.5.x (this train) | degraded set (7.5) | full |

The doctor shows connected clients by protocol so a mixed fleet is visible. The legacy window:
hydra.4 and hydra.5 serve protocol 2; whether to refuse it from hydra.6 is for the owner then (OD6).

### 5.1 Every change a protocol-2 client can observe

The upgrade gate is **not** the only behaviour change a protocol-2 client can observe: the lane move,
`expect`, validate-before-wait, the import wait, the release of dead clients, cancel of lock waits, the
`status` lock, the progress event and the new request fields all reach a v2 client unless something stops
them. This table is the complete list. **G** rows are gated on `Client.v3()` (a v2 connection sees today's behaviour exactly);
**V** rows are deliberately visible to v2, each with its reason. The 317 request goldens
(`examples/characterization/*.json`, seven scenarios) record **replies only**: their own
docstring excludes progress events, older-format projects, lock timing and file-system dependent
copies, and none of the 317 steps carries `expect` on `signature` or `data_type`. So every row has a
behaviour test of its own, written against the **stock 1.0.0 client** (P1a vendors it as
`examples/stock/ghidra_session_1_0_0.py`, so the test is a real protocol-2 client) in a file
`examples/cc_<package>.py` loaded by `examples/client_compat_tests.py` (the loader is P1a's, like E0's
`dt_*` and `char_*` loaders; each file also runs on its own). Each test records its hydra.3 behaviour
first and must pass unchanged on the hydra.4 candidate.

| # | Change | What a v2 client would notice | Decision and reason | Test (package) |
|---|---|---|---|---|
| G1 | `expect` enforced on `signature` and `data_type` (3.4) | a request that carries `expect` there is ignored today (`Operations.java:157,186` compute the old value and never compare); enforced it would turn a success into `conflict` | **Gated on v3.** Enforcing it for a v2 client that sent a stale `expect` would be a break with no benefit to that client | `cc_e1`: v2 `edit` signature and data_type with a wrong `expect` still succeed; the same request on v3 conflicts (E1) |
| G2 | `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay` move from `long` to `maint` (3.5) | queueing, ordering and the text of `busy` for these commands | **Gated on v3** (`laneOf(cmd, req, v3)`). The benefit is for the Hydralysis commit path, which is v3 | `cc_e3a` `v2_lane_unchanged`: long saturated, a v2 `save` waits and fails `busy` in `long` as on hydra.3; a v3 `save` runs (E3a) |
| G3 | fair key `connection + scope` and the per-key cap (3.5) | the order in which a v2 client's own labelled requests are served | **Gated on v3**: a v2 request keeps the key `connection id` and is never capped | `cc_e3a` `v2_queue_order`: the hydra.3 service order of two labels on one v2 connection is reproduced (E3a) |
| G4 | validate-before-wait (3.5) | a bad request on a full lane fails at once instead of after its wait | **Gated on v3**: timing and which error wins (`bad_request` or `busy`) are observable | `cc_e3a` `v2_no_preflight` (E3a) |
| G5 | the `queue` key of a **slot wait**'s progress events and `status.requests[].queue`, and the import estimate's `estimateScope` (3.4; conditionals C4 and C5) | one more key in an event or a `status` entry. **Premise corrected in revision 3:** an **import** wait already carries `queue` in its progress events and in `status.requests[].queue` in protocol 2 today (`m.waiting("import queue", q)`, `ImportGate.java:188-194`; `RequestMonitor.java:111`), so for the import wait the `queue` key is **not new v3 content and not gated**; only the slot-wait `queue` key (today `Scheduler.admit` calls the one-argument `waiting`, `Scheduler.java:155`) and `estimateScope` are new | **Gated on v3**: `Scheduler.admit` keeps the one-argument `waiting(what)` for a v2 connection, and `ImportGate` (E3a's file, which needs the client: `enter` receives only `c.id`) adds `estimateScope` only for a v3 entry. Events are not replies, so the goldens cannot see them | `cc_e3a` `v2_progress_keys`: the exact key set of every progress event during a slot wait **and** an import wait, equal to hydra.3's (the import wait still carries `queue`, without `estimateScope`) (E3a) |
| G6 | `Scheduler.describe` takes the scheduler lock with `tryLock(250 ms)` and may answer `unavailable` (3.4, `health`) | `status.scheduler` could say `unavailable` instead of blocking | **Gated on v3** (E1 adds the `describe(boolean v3)` overload, which does not exist yet: `Scheduler.java:285` takes no argument; the `tryLock` is behaviour gate 5, the reply shape C2) | `cc_e5` (with `-Dghidra.session.testHooks=true` and `debug_stall` holding the scheduler lock): v2 `status` blocks as on hydra.3, v3 answers `unavailable` (E5) |
| G7 | new request fields: `purpose`, `open`, `verify`, `lane`, `isolation`, `scriptSha256`, `rk` (3.1, 3.4) | a v2 request that already used one of these names with another meaning would change behaviour. None is known (Hydralysis `workcopy.py:266` sends `writable` and a path; the 1.0.0 client and the README examples use none), which is a check, not a proof | **Gated on v3**: one helper reads them, so the answer does not depend on a search. (`backup` on `open_program` is the exception: it is read at any protocol because V1 applies to any protocol) | `cc_e1` (`rk` twice is applied twice), `cc_e2` (`purpose:"backup", open:false` is a plain fork, opened), `cc_e4` (`isolation`, `lane`, a wrong `scriptSha256` have no effect) |
| G8 | the upgrade gate's refusal code (3.3) | a new error code | **Gated**: v2 gets the existing `conflict` with `details.reason:"backup_required"`; v3 gets `backup_required` | `cc_e2` (E2) |
| V1 | the upgrade gate (3.4) | `open_program writable upgrade:true` on a canonical older-format project without a valid `backup` is refused, where it succeeded | **Visible to v2, by design.** The gate exists to stop a one-way upgrade of a project that is not a copy; gating it on v3 would protect nothing from the clients least likely to know. `README.md:1011-1014` already tells people to do it in a copy | `cc_e2` on the legacy fixture (`--legacy-project`): refused for v2 with `conflict`, allowed on a fork and with a valid `backup` (E2) |
| V2 | import wait fix (3.5) | **both directions** (revision 3 corrected "can only gain"): (1) an import without a `wait` field no longer fails `busy` ten seconds after reaching the front; it waits unlimited for the slot and the project lock, as it already does for the gate; (2) an import with an explicit numeric `wait` that spent most of it in the gate now fails `busy` when that one budget is used up, where today its slot and lock waits each got a fresh full `wait` and it could succeed | **Visible to v2**: (1) is a defect fix, (2) makes `wait` the total a caller asked for; no client can depend on either behaviour (a 10-second failure after an hour is not a contract) | `cc_e3a` `import_wait` (no `wait`) and `import_wait_explicit` (a numeric `wait` spent in the gate) on a v2 connection (E3a); `import_wait` fails on hydra.3 by E0's premise test |
| V3 | bounded release of a dead client (3.5): `shutdownNow()` after `cleanupGraceS`, `disconnect` bounded by `abandonWaitS` | other clients get a dead client's slots and locks after about 20 s instead of after an hour (`awaitTermination(1, HOURS)`) or 10 minutes per program (`CLEANUP_WAIT_MS`) | **Visible to v2**: it changes how long *others* wait, no reply shape | `cc_e3b` `dead_client_lock_wait` with a 1.0.0 client killed while blocked (E3b) |
| V4 | a request for a program held by an **abandoned** request answers `busy` at once (3.5) | `busy` immediately, with the existing `holder`/`holderInfo` keys saying "abandoned", instead of waiting out `wait` | **Visible to v2**: waiting for a holder that is gone helps nobody; `details.reason` is v3 only | `cc_e3b` `abandoned_holder` (E3b) |
| V5 | `cancel` (and a `timeout` deadline) now ends a lock wait (3.5) | a cancelled request that waits for a program, project or overlay lock answers `cancelled` within a second; today it keeps waiting until its `wait` ends in `busy` | **Visible to v2**: it is what `cancel` is documented to do. The single timed `tryLock` and its FIFO order are unchanged | `cc_e3b` `cancel_while_waiting` (E3b) |
| V6 | endpoint file and `ready` event gain `protocolMin`, `protocolMax` (3.1) | two extra keys in a file and an event; `protocol` stays 2 | **Visible, additive**: needed for negotiation (D3); the 1.0.0 client reads `protocol` and `minClient` and ignores the rest | `cc_e1` (first test): the 1.0.0 client against the E1 engine connects and works (E1; the harness is P1a's) |
| V7 | every `fork_project` sidecar gains `purpose` and `disposable` (3.4, D12) | a few keys in a file beside the fork; the reply is unchanged | **Visible, additive**: the upgrade gate decides from the sidecar | `cc_e2` `fork_sidecar` (E2) |

The release identity strings (`hydraVersion`, `buildDate`) change with every release; the goldens mask
them (`"hydraVersion": "<masked>"`). `health` is a new command, so an old transcript contains none.
The counts D2 refers to: **thirteen reply-shape conditionals, C1 to C13, one per row of the table in
3.1**; G5 is the behaviour test of C4 and C5, which are events and `status` entries that the goldens
cannot see, while the other eleven are reply shapes that the seven v2 scenarios at `--protocol 2`
check directly (a v2 reply must stay byte-identical); six behaviour gates (G1 and G7 share the
request-field helper; G2, G3, G4, G6 and G8 are one gate each); seven declared visible changes (V1 to
V7).

### 5.2 Release notes (R1) must say

- `minClient` stays `1.0.0` (D4): no existing client is rejected by a hydra.4 engine, and hydra.4
  serves protocol 2 and 3 on one port. The one bump is reserved for the release that drops protocol 2.
- Hydralysis 0.4.x refuses a hydra.4 engine by its own pin (the matrix above); hydra.2/3 clients
  keep working at protocol 2.
- The declared protocol-2-visible changes V1 to V7 of 5.1, by name.
- A harness restart is needed once after the Hydralysis catalog epoch (7.7).

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
- **The overlay lifecycle waits are not cancel-aware.** `openOverlay`, `rebuildOverlays`,
  `dropOverlays` and `promoteOverlay` take untimed `lock()` calls on an overlay's lock
  (`OverlayCommands.java:228, 238, 251, 319, 352, 404`). `cancel`, a `timeout` deadline and the
  dead-client release do not reach a request blocked there (3.5); the three request-bound timed
  waits are what E3b converts.
- **A stalled call on hydra.2/3 is abandoned, not ended.** The client's deadline half-closes its
  connection and abandons a worker thread (7.6); the engine keeps the request, its slot and any lock
  until it ends by itself, and a request in a script that never polls its monitor can hold them for as
  long as it runs. At most 8 abandoned connections per process are tolerated; the real remedy is
  E3b's bounded release on hydra.4.
- **The `lane:"quick"` hint is trust-based.** The engine cannot know that a script is quick. It
  honours the hint for `0 < timeout <= quickScriptMaxS`, and the `timeout` only sets the request's
  cancel flag (`m.deadline`, `ScriptCommands.java:75`): a script that never polls
  `monitor.checkCancelled()` keeps its **quick** slot past its timeout, and enough of them starve the
  quick lane, which the long lane would otherwise absorb. RusticQuery polls (17 sites) and is hash-pinned;
  an arbitrary user script that claims `quick` is not policed. The lane figures in `health` show it
  (`longestRunningMs` past the hint), and the remedy is the same helper JVM that is out of scope.
- **History is capped by records and bytes, and pending records are not compacted.** Committed records
  are archived (4.2), but a store with 4096 pending records, or 20 MiB of them (`effects` make a
  record larger than a v2 one), cannot take another edit until some are committed (a subset commit
  works) or exported as a bundle; nothing is dropped automatically.
- **An append log is bounded by what Y2 builds.** Until the Y0e/Y2 change of 4.1 (streamed reads, tail
  window, rotation) lands, a `CURRENT.log` or `backups.log` of more than 32 MiB (`localio` budget)
  makes readers and writers raise. At one line per commit or backup this is far from any realistic
  size, and it fails loudly, never silently.
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
  today). **The same blindness reaches a subset commit** (4.2): the selection closure is per coarse
  subject, so `only` can ship a `signature` or `data_type` edit without the pending struct it uses.
  4.2's `subset_missing_type` test decides whether that fails closed; until it has run, subset commits
  carry "no semantic dependency tracking" in their documentation.
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

One module, one shape: `backend action=doctor` and the CLI command that wraps the same handler.
`cli.py` had **no owner**, so Y0d could not expose `backend --action doctor|backups` or `--options`
there; it is Y0e's in W1 (8.2): the CLI passes the action and an `--options` JSON object straight
through to the same dispatcher as the MCP tool, so no later package edits `cli.py`. It is read-only and **never starts a JVM
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

- **Probe** `health` every 5 s while the engine is in use, on a **dedicated connection** and with a
  deadline: P1b's `deadline` on a hydra.4 client library, the deadline helper of 7.6 (half-close and
  abandon) against a hydra.2/3 engine (where `health` does not exist either and the probe is `ping`,
  7.5). A probe that expires abandons its connection and the next probe opens a new one, so the
  supervisor counts abandoned connections (a cap of 8 per process, 7.6) as a finding of its own.
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
| `health` | `ping` with a deadline (the deadline helper of 7.6, one connection per call: P1b is not available there); wedge detection needs the pid and the lock only |
| deadlines (`deadline_s`) | the 7.6 helper (worker thread, `cancel`, half-close, abandon); P1b's `deadline` only when the engine ships library 1.1.0 |
| `rk`, `expect` on signature/type | not used; Hydralysis does not rely on them |

### 7.6 Lane hints, deadlines, error contract (Y4a, Y0b)

- Reads: `query.run_script` (`query.py:76-91`) adds `lane:"quick"` (its `timeout` already is
  `timeout_s + 5`); `fork_project` and `save` need no hint (they are maint by command on a v3 connection).
- Deadlines: a quick-lane call carries `deadline_s` (default 60 s); long-lane calls none. The mechanism
  depends on the engine, because Hydralysis loads the session library **from the engine install**
  (`hydra.py:229-233`):
  - *hydra.4 (library 1.1.0, P1b):* `call(cmd, deadline=...)`; on expiry the library sends `cancel
    target=<id>` and raises `deadline_exceeded`, and the connection stays usable. Nothing is
    abandoned.
  - *hydra.2/3 (library 1.0.0): half-close and abandon.* Revision 2 specified `session.close()` on a
    timer; **that does not work on 1.0.0** (it hangs and sends nothing, shown below) and is withdrawn.
    The mechanism that replaces it was chosen by experiment against the real 1.0.0 library and a
    real hydra.3 daemon and is the sub-section that follows. In one line: the deadline is a
    worker-thread `send`/`wait` that the **caller** never enters; on expiry send `cancel` through
    the same session, wait a grace, then `shutdown(SHUT_WR)` the socket, **never** `close()` or touch
    the library's file objects, and abandon the worker thread and the connection; the engine's view
    on hydra.3 is that the request goes on until it ends by itself, so the client **never relies on
    an EOF or a reply coming back**.
- Waits: `BUSY_WAIT_MS` (180 s, `query.py:29`) and `SYNC_LOCK_S` (900 s, `workcopy.py:33`) shrink to a
  patience budget (default 25 s) once the engine reports queue information; beyond it the tool call
  returns the engine's structured `busy` (queue position, `retryAfterMs`, `next`), not a hang. No
  detached-call state is introduced (D24).
- `EngineError` (`hydra.py:51-63`) keeps `holder`, `holderInfo`, `heldMs`, `queue`, `retryAfterMs`,
  `current`, `next`, with the **informational lists** (`queue`, `running`, `alternatives`, the holder
  lists) capped at 5 entries plus `more`. The cap never applies to `next`: it is a ready request and
  must stay complete (the Y0b review showed a recursive cap cutting `next.args` to 5 entries; Y0b's
  code is to be corrected in W1 by Y0e, 8.2).
- Pools: the MCP server splits PE-only tools (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`,
  `callers`, `callees`, `function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_*`) from tools
  that talk to the daemon, so four blocked engine calls (`TOOL_WORKERS = 4`, `mcp.py:22`) cannot starve
  them (Y0c). **`MAX_OUTSTANDING` is per lane** (decided; it is what Y0c shipped): each pool has its
  own budget of 8 accepted calls and its own 4 workers, so the total outstanding can reach 16 and a
  saturated engine lane never makes a local tool answer `busy`. The `busy` answer of the MCP layer
  names the lane and carries its retry hint as **text** (`retryAfterMs=2000` in the message) until the
  engine's structured `busy` (queue position, `retryAfterMs`) exists; a client cannot parse the MCP
  text and does not need to. Known edge: `prologue` with `checks` and a `session` can call the
  runtime runner on the fast lane (`api.py`, a runtime call that may block outside the engine lane);
  it stays on the fast lane because the PE-only list above names `prologue`, and enough hung live-session
  prologue calls could occupy the four fast workers: a follow-up for Y4b's doctor to report, not a
  change here.

#### The hydra.2/3 deadline mechanism (tested)

**What is wrong with `session.close()`** (the finding of the second review, reproduced here on the real
object). `SocketSession.close()` (`ghidra_session.py:866-874`) closes the two `makefile` objects (`_w`
then `_r`) and only then calls `sock.shutdown`. A thread inside `wait()` sits in `_r.readline()`
(`:753`) holding `_read_lock` (`:748`); closing `_r` waits for the buffer lock that `readline` holds,
so `close()` called from a second thread never gets as far as `shutdown`: nothing is sent, the
engine sees no FIN, and the blocked `wait` does not raise. `sock.shutdown(...)` on its own returns at
once and **does** deliver the FIN, but it does not wake the blocked reader either. Candidates
tested: **(a)** abandon the session and its reader thread without touching it; **(b)**
`shutdown(SHUT_WR)` only, makefiles untouched; (b') (b) plus `sock.close()` (deferred by the
makefile references); `SHUT_RDWR`; **(c)** detach the OS handle and close it abortively
(`SO_LINGER` 0); and the withdrawn `close()`. Scripts and recorded output are in
`D:/Projects/Hydra/_logs/spec-rev3/`: `exp1_client_matrix.py` (real `SocketSession`, fake server,
`exp1_out_py3.14.txt` and `exp1_out_py3.15.txt`), `exp2_engine.py` (real `hydra-3-candidate`
daemon, fresh state root `work-*/state`, output `run1/exp2_run_with_cancel_L_S.log`,
`exp2_run_nocancel_LSC.log`, digest `exp2_summary.txt`) and `exp3_lifecycle.py` (`exp3_out_py*.txt`).
Python 3.14.7 and 3.15.0 on Windows 11 gave identical rows; the library of `hydra-2` and the one in
`hydra-3-candidate` differ only in `HYDRA_RELEASE` (a `diff` of the two files).

*Client side* (`exp1`; one thread blocked in `wait(rid)`, a second thread applies the mechanism; the
server is silent or closes its end when it sees EOF, which is what a cooperative engine does):

| Mechanism | The call | Reaches the server | Blocked `wait`, engine silent | Blocked `wait`, engine closes | A later `send` |
|---|---|---|---|---|---|
| `session.close()` (revision 2) | **hangs** (> 5 s) | nothing | still blocked | still blocked | `ValueError` |
| (a) abandon | returns | nothing | still blocked | still blocked | works |
| (b) `sock.shutdown(SHUT_WR)` | returns at once | **FIN** | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| (b') `SHUT_WR`, then `sock.close()` | returns | FIN | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| `sock.shutdown(SHUT_RDWR)` | returns | FIN | still blocked | raises `SessionError("closed")` | `BrokenPipeError` |
| (c) detach, `SO_LINGER` 0, close | returns | **RST** | raises `OSError` (WinError 10053) at once | same | `OSError` |

*Engine side, real hydra.3* (`exp2`: the 'doomed' client's request is **L** a `decompile` blocked
for the program lock that another client's cooperative script holds (about 35 s), **S** a script
that ignores `cancel` and swallows interrupts for 40 s, **C** a cooperative script; the client
sends `cancel` after 3 s and the mechanism 3 s later (run 1) or only the mechanism (run 2, to see
the effect of the FIN alone); an observer connection reads `status` every few seconds):

| Mechanism | L: lock wait | S: non-cooperative script | C: cooperative script (run 2) |
|---|---|---|---|
| `close()` | call hangs; the engine sees nothing: client and request stay registered, released 0.5 s after the holder ended | hangs; released when the script ends (40.1 s) | not run |
| (a) abandon | **never released**: 30 s after the holder ended the client is still listed and still a `users` entry of the program (`users:[2,4]`, `registered:true`) | **never released**: still listed, `requests:[]`, after the script ended | not run |
| (b) `SHUT_WR` | `status.requests[].cancelled` false then true within 1 s of the FIN (run 2); the request stays registered with its lock wait until the holder ends, released 0.5 s later; the reply `cancelled` reaches the client then (after 21.3 s) | cancelled flag set, the script runs on, released when it ends (40.1 s), reply `cancelled` | **released 0.1 s after the FIN; the reply reached the client's waiter 0.01 s after it** |
| (c) abort | as (b); the daemon log says `client N (...): Connection reset` | as (b) | released 0.1 s after the RST; the waiter raised `ConnectionAbortedError` |

**What the engine sees on hydra.3, in words.** A FIN (or RST) ends `Connection.run`'s read loop; its
`finally` sets `client.leaving`, calls `cancel()` on every running monitor (seen: the request's
`cancelled` goes false to true within a second) and then waits in `awaitTermination(1, HOURS)`
(`Connection.java:93-108`) for the request threads. It does **not** close the socket and does not
unregister the client until they end. A request that polls its monitor ends at once and the
client is released and answered (C). A request in a **lock wait** keeps its place in the lock's
queue (hydra.3 does not end a lock wait on `cancel`, E0 `cancel_lock_wait`) and the program stays
held by its client until the lock frees (L). A request in a script that **never polls** the monitor
keeps its slot, and any lock, until the script ends (S). Therefore **the client must never rely on
an EOF, or on any reply, coming back from hydra.3** to end its wait: only the cooperative case
answers.

**The mechanism (specified; Y4a, `hydra.py`).**
1. *One connection per deadline-bound call*, taken from a small per-`role` pool (`hydra.py:227`)
   and returned to it only after a normal reply; a connection that was abandoned is never reused.
   No other call is ever in flight on it, so nothing else fails when it is abandoned.
2. The call is `rid = session.send(...)` plus `session.wait(rid)` **in a daemon worker thread** of
   Hydralysis; the caller waits on its own `threading.Event` with the timeout `deadline_s` and never
   enters `wait`. A mutating call never gets a deadline that abandons (4.3).
3. On expiry the worker's session gets `session.send("cancel", target=rid)` (thread-safe, `:732-738`;
   it ends a request still waiting for a slot, and a cooperative one) and the caller waits
   `deadline_grace_s` (5 s) more for the reply.
4. If there is still none: `session.sock.shutdown(socket.SHUT_WR)`. **Nothing else**: no
   `session.close()`, no `_r.close()`, no `sock.close()` while the worker is alive, and no `send` on
   that session afterwards (a `send` after the half-close raises `BrokenPipeError` and leaves
   buffered text that the `_w` finalizer reports on stderr, seen in `exp1_err_py*.txt`). The caller
   gets `deadline_exceeded` with `details.connection_abandoned:true` after `deadline_s +
   deadline_grace_s` (measured 2.01 s for 1 s + 1 s, `exp3`, C).
5. The worker ends by itself when the engine answers or closes the connection, and then closes the
   session **itself** (nothing is in `readline` any more: measured 0.0 s, `exp3`, A) and leaves the
   registry. Abandoned workers are counted in a process-wide registry; **at most 8** at a time
   (*unmeasured policy*: 40 abandoned connections cost 40 daemon threads and 40 sockets and all end
   when the engine closes them, `exp3`, B); beyond the cap a deadline-bound call fails fast with
   `daemon_unhealthy` and the doctor (7.1) lists the stuck requests, which is what an operator
   needs on a daemon where eight requests ignore cancel.
6. Rejected: `close()` on a timer (hangs); abandon alone (the engine keeps the client and the
   program's `users` entry for good, measured); the abortive close (c), which works on Windows and
   wakes the reader, but reaches into the library's private `sock` with `detach()`, raises a raw
   `OSError` out of `wait` that 1.0.0 does not handle (`_closed` stays unset), depends on Winsock
   behaviour, and buys only the early end of one thread.

**What changes with P1b and E3b.** On a hydra.4 engine the library is 1.1.0 and P1b's `deadline`
replaces steps 1 to 5 (the library times its own `wait`; the connection survives, so nothing is
abandoned). E3b (V3, V5) also changes what the engine does with the half-close of an old library:
a request in a lock wait now ends within a second of the `cancel` or the FIN, and a request that
does not end is released after `cleanupGraceS + abandonWaitS` (about 20 s) with the program
flagged `abandoned`, instead of staying registered for as long as it runs. Until then the cap of
step 5 is the protection.

**Tests (Y4a).** Against the fake: a blocked session never has `close()` called while its worker is
alive (a fake that fails the test if it is); the caller gets `deadline_exceeded` at `deadline_s +
deadline_grace_s`; the abandoned count never passes 8 and returns to 0 when the fake closes. Against
the **real hydra.3**, one test per case above (L, S, C of `exp2`, reduced in time): the dedicated
connection is replaced and the other connections are untouched; the engine shows the cancelled flag
within 1 s of the half-close; C is released within 1 s and the call returns the engine's reply;
L and S stay registered until the holder or the script ends and then the abandoned worker ends and
the registry is empty.

### 7.7 The 20 tools: where each feature lives

The 20 tools stay (`fingerprint`, `imports`, `disasm`, `inspect`, `xrefs`, `callers`, `callees`,
`function`, `bytes`, `strings`, `sigscan`, `prologue`, `evidence_add`, `evidence_list`, `ghidra_run`,
`ghidra_query`, `backend`, `prepare`, `job`, `runtime`). One catalog epoch in Y0d, before the 0.5.0
tag, then a hash-checked freeze. **Where the epoch is reported (decided, and what shipped in Y0d):
`backend action=status` and `backend help` carry `catalog:{epoch, hash}`, and nowhere else**:
`ghidra_query action=status` is a target status built in `query.py` (a different file, owned by
Y1/Y2/Y3) and is about a target, not about the tool surface; `backend inspect` and the MCP
`initialize` reply (`mcp.py`, Y0c, closed) do not report it. The hash covers only the advertised tool
table (names, descriptions, input schemas), **not** the `instructions()` text or the help output
(a deviation Y0d disclosed and this section accepts): a change to either needs a manual epoch bump,
which a reviewer checks, because no test can see it.

| Feature | Carrier |
|---|---|
| edit with `expect_revision`, named view | `ghidra_query action=type_edit options.{kind,expect_revision,view}` (exists) |
| commit, revert, rebase, publish, merge, export/import bundle | `type_edit options.kind = commit | commit_revert | rebase | publish | merge | export_bundle | import_bundle` (no address needed, like `struct` and `revert` today) |
| changes against master, views, lineage, queue, health | `ghidra_query action=status options.show = changes | views | lineage | queue | health` |
| commit/backup/publish jobs | `job` (existing `status`/`cancel`), jobs of kind `commit` |
| doctor | `backend action=doctor` (new enum value, Y0d; the handler is `doctor.py`, Y4b; reachable from the CLI too, 7.1) |
| list, verify backups and generations | `backend action=backups` with `options.op = list | verify` (new enum value and an `options` bag, Y0d) |
| user-script mode | `ghidra_run options.{isolation, readonly}` (`options` bag added in Y0d; `view` exists; until Y4e ships a non-empty bag answers `not_available` instead of running, a Y0d decision that is kept: nothing is silently dropped) |
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

Conventions that make the waves disjoint (the matrix in 8.1 is the authority; this is how it is kept true):

- **One owner per file per wave.** 8.1 lists, for every file a package edits, the one package that may
  edit it in each wave. Two packages in one wave never share a cell. A package that needs a file that
  another package owns in its wave waits for the next wave or asks for a seam first (D31). A new file
  belongs to the package that creates it, in that wave and later ones until another is named.
- **Seams first (D31).** The shared files every feature wants to touch are opened once, early, as
  behaviour-free seams by E1 (W1): the two signature changes of D17 and their call sites
  (`Scheduler.laneOf`/`admit`, `Session.java:248`, `ImportCommands.java:112`), the call sites of
  `ProjectEntry.info(client)` (a signature only, so that E2's `format` needs no `Session.java` edit), and
  four registries (`Advertised`, `Settings`, `Preflight`, `DbVersions`). Later packages
  register into them from classes they own. So `Session.java` is edited by E1 (W1), E3b (W3) and
  E5 (W4) and by no one in W2, and E2 and E3a, which run in parallel in W2, share no file.
- E0 adds loaders so each package adds tests in its **own** files: `examples/dt_<package>.py` for
  daemon tests (each exposes `TESTS = {name: fn}`; `daemon_tests.py` imports `dt_*.py`),
  `examples/char_<package>.py` for characterization scenarios, with goldens in
  `examples/characterization/v3/<scenario>.json` (recorded with `--protocol 3`), and P1a adds the third
  loader, `examples/cc_<package>.py` for the protocol-2 behaviour tests of 5.1. The seven existing
  scenarios run at `--protocol 2` and must stay `identical`.
- **`certification.manifest` is the one deliberate exception** to "one owner per file per wave": every
  package appends its new files to it (the `buildHeadless` IP check fails otherwise), it is append-only,
  and a textual merge conflict is resolved by keeping both lines. (R1's own line items are its
  release entries; the append rule holds for every package, R1 included.) **`PROTOCOL-3.md` is the
  design**, a different file: packages do not edit it (a design change is a new revision by the
  coordinator, with the history at its end), and status lives in the stream reports under
  `D:/Projects/Hydra/_logs/<stream>/`. README and CHANGELOG are edited by R1 alone, from the
  packages' hand-over notes.
- **A package that changes the format of a stored file owns the existing tests that write that file by
  hand.** Y0a sealed every record file, so two older tests that hand-edit a store or a record and keep
  its stale seal had to drop the seal (`record.pop("seal")`, commit `c78be27`: `tests/test_address_maps.py`
  and `tests/test_query.py`); 8.1 now gives those two files to Y0a explicitly (W0), and Y1 owns the
  tests that hand-write a store when it moves to store v3. The same applies to later format changes.
- Hydralysis hotspot files (`workcopy.py`, `query.py`, `analysis.py`, `hydra.py`, `api.py`,
  `tests/fakehydra.py`) have one owner per wave (8.1). **`api.py` is opened once**: Y2 (W2) replaces
  Y0d's `not_available` stubs with a **handler registry** (an action or option name to a callable;
  modules `backups.py`, `commits.py`, `doctor.py` and `userscripts.py` register their handlers, and
  `api.py` imports a fixed list of handler modules lazily and answers `not_available` for a module
  that does not exist yet), so Y4b, Y4d and Y4e never edit `api.py`: the `ghidra_run` `options`
  (`isolation`, `readonly`) dispatch, the `job` `options` and the `backend` `doctor` and `backups`
  actions each have a named owner and wave in 8.2, which is the seams-first rule of D31 applied to the
  Python side.
- `examples/check_ownership.py` (E0) reads the matrix in 8.1 and fails when a wave cell names two packages
  or when the files changed on a package branch (`git diff --name-only` against its base) are not
  all in that package's rows for its wave; it runs at every package merge (gate 9.11).
- All engine tests use fresh state roots under `D:/Projects/Hydra/_logs/<stream>/` and a fresh
  `--tmpdir`; they never touch the live daemons.

### Wave plan (compact)

| Wave | Hydra (engine) | Hydralysis | Notes |
|---|---|---|---|
| W0 baselines and hardening | E0 | Y0a, Y0b, Y0c, Y0d | no engine behaviour change; all parallel; disjoint files (8.1). |
| W1 foundation and seams | P1a, then E1 | Y1, Y0e | E1 owns every shared-file seam (`Session.java`, `Scheduler`, `ImportCommands`, `UpgradeCache`, `ProjectCommands`, `ProjectEntry` (signature only), `HeadlessSession`, and the new `Advertised`, `Settings`, `Preflight`, `DbVersions`); P1a owns `ghidra_session.py` and the protocol-2 compatibility harness and lands first (E1's `cc_e1.py` needs its loader and the vendored 1.0.0 client); Y0e takes the W0 review follow-ups that no W0 package could own (8.2); all disjoint |
| W2 facts, gates, lanes | E2, E3a | Y2 | **neither edits `Session.java`** (E1 placed the seams). E2: format, backup, gate, fork; it names no lane. E3a: `Scheduler`, `ImportCommands`, **`ImportGate`**, `Requests`, `Connection.respond`, `RequestMonitor`; it decides the lane and the lane note. A backup reaches the `maint` lane through E3a's command mapping, with no code dependency between the two; the combined test is E6's |
| W3 robustness | E3b | Y3 | E3b owns `Waits`, `Caller`, `Access`, `ProgramEntry`, `OverlayCommands`, `Connection`, `RequestMonitor`, `Session.disconnect`, `ProjectCommands.leaveProject`, `ProgramCommands.releaseUse` |
| W4 isolation, health, launcher | E4, E5, P1b | (catch-up) | E4 after E3b (both touch `OverlayCommands`); E5 owns `Session.java`, `Scheduler`, `HeadlessSession`; disjoint |
| W5 soak and release prep | E6, then R1 | | R1 owns `tools/bump_hydra.py` and the docs and runs after E6 (it depends on every engine package, E6 included); then **gate G** (section 9) |
| W6 adoption on hydra.4 | | Y4a, Y4b, Y4d, Y4e | disjoint files; Y4a runs R1's `bump_hydra.py` and owns the files it edits. The package ids are Y4a, Y4b, Y4d and Y4e: **there is no Y4c** (the ids keep the labels of the first draft) |
| W7 deferred | | Y5 | only after its preconditions |

### 8.1 File-ownership matrix (the disjointness assertion)

Every file a package edits, by wave. `S/` is `src/main/java/ghidra/app/util/headless/session/`; **bold**
marks a file the package creates. A blank cell means no package edits the file in that wave. **Assertion:
no cell names more than one package** (so each wave is disjoint by construction, and
`check_ownership.py` verifies it); `certification.manifest` is the one stated exception (above). Tests: `dt_*`, `char_*` and `cc_*` files, vectors and fixtures belong to the package
whose name they carry and appear in its package text.

**Hydra (engine repo)**

| File | W0 | W1 | W2 | W3 | W4 | W5 |
|---|---|---|---|---|---|---|
| `S/Session.java` | | E1 (hello, `info`, `admit` call with the request, the call sites of `ProjectEntry.info(client)` at `:265`, `:333`, `:427`, `isInline` stays) | | E3b (`disconnect`, `reap`) | E5 (`isInline`, `case health`, watchdog start) | |
| `S/Scheduler.java` | | E1 (`laneOf(cmd, req, v3)`, `admit(c, cmd, req, m, waitMs)`, `describe(boolean)`, all behaviour-free) | E3a (maint lane, fair key, cap, queue info, ETA, `Preflight` call) | | E5 (`describe` `tryLock`, lane stats) | |
| `S/ImportCommands.java` | | E1 (the `admit` call at `:112` only) | E3a (remaining wait; the `ImportGate.enter` call at `:100` passes the client) | | | |
| **`S/ImportGate.java`** | | | E3a (`enter` takes the `Client`, `Entry` keeps it, `queueInfo` adds `estimateScope` for v3) | | | |
| `S/Connection.java` | | E1 (`error()` gets the client and emits `next`, `retryAfterMs`) | E3a (`respond`: `queue` header) | E3b (`run`: grace, `shutdownNow`; `respond`: `cancelled` details `applied`, `phase`) | | |
| `S/RequestMonitor.java` | | | E3a (queue, lane and lane-note carriers) | E3b (wait registration, `cancel()` override) | | |
| `S/Requests.java` | | | E3a (generic `Preflight` checks) | | | |
| `S/Caller.java`, `S/Access.java`, `S/ProgramEntry.java`, **`S/Waits.java`** | | | | E3b | | |
| `S/OverlayCommands.java` | | | | E3b (lock site) | E4 (`loadOverlay` extracted) | |
| `S/ProjectCommands.java` | | E1 (the call sites of `ProjectEntry.info(client)` at `:92`, `:395`) | E2 (`openProject` `format`) | E3b (`leaveProject`) | | |
| `S/ProgramCommands.java` | | | E2 (`openWritable` gate) | E3b (`releaseUse`, `closeEntry`) | | |
| `S/UpgradeCache.java` | | E1 (`currentDbVersion` moved to `DbVersions`) | E2 (`readStored`) | | | |
| `S/EditCommands.java` | | E1 (`withLastEditor`, `rk`) | E2 (`save` stamp) | | | |
| `S/ForkCommands.java`, `S/ProjectFork.java`, **`S/ProjectFormat.java`**, **`S/ProjectBackup.java`** | | | E2 | | | |
| `S/ProjectEntry.java` | | E1 (`info(Client)`: the signature only, same value) | E2 (`format` for v3) | | | |
| **`S/DbVersions.java`** | | E1 (`program()`, `dataTypes()` returning `null`) | E2 (`dataTypes()`) | | | |
| `S/Operations.java`, `S/Journal.java`, `S/Client.java`, `S/SessionException.java`, **`S/Identity.java`**, **`S/Advertised.java`**, **`S/Settings.java`**, **`S/Preflight.java`** | | E1 (`SessionException`: the new codes, the busy-details and the bad-request-details helpers) | | | | |
| `S/HeadlessSession.java` | | E1 (endpoint and `ready`, `-set`) | | | E5 (watchdog start) | |
| `S/HydraInfo.java` | | E1 (protocol constants) | | | | R1 (version) |
| `S/ScriptCommands.java`, **`S/PrivateInstance.java`** | | | | | E4 | |
| **`S/Health.java`**, **`S/Watchdog.java`** | | | | | E5 | |
| `support/ghidra_session.py` | | P1a (range, `engine` pass-through) | | | P1b | |
| `examples/daemon_tests.py`, `examples/characterization_tests.py`, **`examples/check_ownership.py`**, **`examples/dt_baseline.py`**, `examples/characterization/v3/` (created by E0 as an empty directory with the loader) | E0 | | | | | |
| `examples/contract_tests.py` | | E1 (the protocol and first-`hello` tests) | | | | |
| `examples/client_compat_tests.py`, **`examples/stock/ghidra_session_1_0_0.py`** | | P1a | | | | |
| `examples/soak_tests.py` | | | | | | E6 |
| `format-matrix.json`, `examples/format_gate.py`, `examples/make_legacy_fixture.py`, `examples/vectors/canonical-manifest.json` | | | E2 | | | |
| `README.md`, `CHANGELOG.md`, `ARCHITECTURE.md`, release workflow | | | | | | R1 |

**Hydralysis (`src/hydralysis`, `tests/`, `tools/`)**

| File | W0 | W1 | W2 | W3 | W5 | W6 |
|---|---|---|---|---|---|---|
| `backends.py` | Y0a | | | | | |
| **`durable.py`** | Y0a | Y0e (streamed log reads, the every-acquisition tail check, 4.1) | | | | |
| `tests/test_durable.py` | Y0a | Y0e (the two-process test, the large-log test) | | | | |
| `tests/test_address_maps.py`, `tests/test_query.py` | Y0a (one line each: drop the stale seal of a hand-edited record; commit `c78be27`) | | | | | |
| `hydra.py` | Y0b | Y0e (`write_daemon_config` through `durable.atomic_write`; `EngineError` cap exempts `next`) | | | | Y4a |
| `tests/test_client.py` | Y0b | Y0e (move the `unittest.main()` guard to the end of the file) | | | | |
| `tests/fakehydra.py` | Y0b | | Y2 | | | Y4a |
| `mcp.py`, `tests/test_mcp_transport.py` | Y0c | | | | | |
| `api.py` | Y0d | | Y2 (the handler registry that replaces the Y0d stubs, 8) | | | |
| `workflow_help.py`, `tests/test_contracts.py` | Y0d | | | | | |
| **`cli.py`** | | Y0e (`backend --action doctor` and `--action backups`, `--options`, passed through to the dispatcher) | | | | |
| `runtime.py`, `runtime_worker.py` | | Y0e (`_write` through `durable.write_json`) | | | | |
| `workcopy.py` | Y0a (`_save_store`, `load_store`) | Y1 (v3 store, `has_overlays` and `expected_state` through `durable.exists`, `require_seal=True`) | Y2 | Y3 | | |
| `targets.py`, `overlayjobs.py` | Y0a | | Y2 | | | |
| `revisions.py`, `analysis.py`, **`annotations.py`**, `scripts/RusticQuery.java` | | Y1 (`analysis.py`: new kinds, and the legacy v1 writer is deleted, 8.2) | | | | |
| `query.py` | | Y1 (`status show=changes`) | Y2 (`stop`, `show=lineage`) | Y3 | | Y4a |
| `exporting.py` | | | Y2 | | | |
| **`lineage.py`**, **`commits.py`**, **`backups.py`** | | | Y2 | | | Y4d |
| **`views.py`** | | | | Y3 | | |
| **`doctor.py`** | | | | | | Y4b |
| `userscripts.py` | | | | | | Y4e |
| **`tools/bump_hydra.py`** | | | | | R1 | |

Per wave the disjointness reads off the columns: W0 = {E0 | Y0a | Y0b | Y0c | Y0d}, each with its own
files; W1 = {P1a, then E1 | Y1 | Y0e}; W2 = {E2 | E3a | Y2}; W3 = {E3b | Y3}; W4 = {E4 | E5 | P1b}; W5 = {E6 | R1};
W6 = {Y4a | Y4b | Y4d | Y4e}. Across waves a file may change hands only in the order the columns show,
and a package depends on the packages whose files it builds on (the lists below).

### 8.2 Ownership of what the first reviews found unowned

Reviews of the W0 packages (Y0a to Y0d, E0) found files and behaviours that the matrix of revision 2
gave to nobody. Each now has one owner and one wave. Y0e is the package that carries the W0 follow-ups
no W0 package could take (the W0 packages are closed; Y0e's files are disjoint from Y1's in W1).

| Gap found | Owner | Wave | Decision |
|---|---|---|---|
| `cli.py` had no owner: spec 7.1 says doctor is also a CLI command, and Y0d could not expose `backend` `doctor`, `backups` or `options` there | **Y0e** | W1 | `cli.py` passes `--action` and an `--options` JSON object through to the same dispatcher as the MCP tool; no later package edits it |
| `api.py`: Y0d's stubs (`ghidra_run` `options.isolation`/`readonly`, `job` `options`, `backend` `doctor`, `backups`) need a replacement in the waves where Y2, Y4b, Y4d, Y4e deliver their handlers, and the matrix gave `api.py` to Y2 and Y4b only (two packages in W6 would have needed it) | **Y2** | W2 | Y2 builds a **handler registry** once (8): `backend backups` goes to `backups.py` (Y2, W2); `job` `options` (`kind`, `cid`) to `commits.py` (Y2, W2); `backend doctor` to `doctor.py` (Y4b, W6); `ghidra_run` `options` to `userscripts.py` (Y4e, W6). `api.py` has a cell in W0 (Y0d) and W2 (Y2) and none after; until a handler's module exists the answer stays `not_available` |
| `workcopy.has_overlays` and `workcopy.expected_state` pre-check the **main** store path (`_store_path(...).is_file()`) and so bypass the `.bak` fallback: with the main file deleted and `.bak` intact, `load_store` answers but these two say "no overlays" | **Y1** | W1 | both use `durable.exists` (a store exists if the main file or its `.bak` does) and call `load_store`; test: delete the main store, keep the `.bak`, both report the overlays |
| A v3 store is read with `require_seal=True`: with the default (`False`) a hand-stripped seal loads as a "pre-seal" v2 record and gives no tamper or truncation signal | **Y1** | W1 | `load_store` reads a version-3 file with `require_seal=True` (a file without a seal is `store_corrupt`); a version-1 or -2 file is still accepted unsealed once and sealed by its first write |
| `AppendLog` reads whole logs through `localio.read_bytes` (32 MiB budget) and checks the tail on the first append of a process | **Y0e** | W1 | 4.1 item 3: streamed reads, tail window, the every-acquisition check with the size comparison, the two-process test; until it lands the 32 MiB limit is recorded in section 6 |
| `EngineError` caps every list recursively, including `next.args` | **Y0e** | W1 | cap only the informational lists (7.6); `next` is exempt; test with an 8-argument `next` |
| `tests/test_client.py` puts the `EngineRetryPolicy` class after `if __name__ == "__main__"` | **Y0e** | W1 | move the guard to the end |
| Y0a edited `tests/test_address_maps.py` and `tests/test_query.py`, which it did not own | **Y0a** | W0 | amended: the two files are Y0a's explicitly in 8.1 (a package that changes a stored format owns the tests that hand-write it, 8) |
| `MAX_OUTSTANDING` per lane or global (Y0c) | decision | | **per lane** (7.6): 8 for the engine pool and 8 for the fast pool, total up to 16 |
| Where `catalog:{epoch, hash}` is reported (Y0d) | decision | | `backend action=status` and `backend help` only (7.7) |
| `canonical()` seals an unpaired surrogate (`surrogatepass`) while 3.4 says it is refused | decision | | tolerated in **seals and bundles** (Python-only forms; 3.4, 4.1 item 2), refused in **manifests** (cross-language); 3.4 says so |
| `*.tmp` files of killed writers are never swept | **Y4b** | W6 | the doctor reports and offers the removal; nothing deletes automatically (D28) |

**Record-bearing writers that stay outside `durable` after Y0a** (the AST write gate in
`tests/test_durable.py` at `589432e` freezes them as a ratchet; a **new** write site fails the gate and
its author adds it to this table):

| Writer | What it writes | Owner | Wave | How |
|---|---|---|---|---|
| `analysis.save_overlay` | the legacy v1 overlay store (no production caller; tests only) | Y1 | W1 | deleted; the tests that call it write fixtures through `workcopy._save_store` |
| `hydra.write_daemon_config` | the daemon's `config.json` | Y0e | W1 | `durable.atomic_write` (fsync and write-through replace) **without a seal**: the engine's launcher reads this file and must see the plain JSON it expects |
| `runtime._write` | runtime session state | Y0e | W1 | `durable.write_json` (sealed) |
| `runtime_worker._write` | runtime worker state | Y0e | W1 | `durable.write_json` (sealed) |
| 22 artifact writes (logs, exports, staged script copies, download and install renames) and 11 non-record writes in the four owned files | logs, exports, copies | none | | not records; frozen by the ratchet |

### W0

**E0 (Hydra, M): failing tests first and the test loaders.**
Goal: baselines and loaders before any engine change.
Files: `examples/daemon_tests.py` (loader for `dt_*.py`, `--only` over them), `examples/characterization_tests.py`
(`--protocol {2,3}` sent in `hello`; loader for `char_*.py`; goldens dir `characterization/v3/`),
new `examples/dt_baseline.py`, new `examples/check_ownership.py` (the 8.1 assertion).
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
3.6; on hydra.3 it did show it: 94 of 115 polls, so the premise stays); `fork_save_behind_analysis` (timing of `fork_project`/`save` while the long lane is saturated);
`cancel_lock_wait` (a request waiting on a program lock is cancelled by id: today it keeps waiting and
ends `busy` when its `wait` ends, `ProgramEntry.java:195`; this is the premise of V5 and of 3.5's
cancel-aware waits).
`import_wait` must fail on its premise for the **third** import, the one that reaches the front: it
shows about 20 s (10 s in the gate and 10 s for the slot), not merely `busy` at 10 s for every import
(the first two fail at 10 s because they were admitted to the gate at once); the test asserts
`max(importsMs) >= 19000`. `characterization_tests.py --protocol 3` against an engine that serves no v3
returns a SKIP (exit 0) unless `--require-v3` is given; **gate 9.3 always passes `--require-v3`**.
Acceptance: the seven scenarios report `identical` at `--protocol 2`; the tests fail on hydra.3 as stated,
or, for a premise that does not hold, are dropped from the design and recorded as a finding (E0's
own convention above; at `c774d9e7b1` all six were `CONFIRMED` on hydra.3 in two runs,
`D:/Projects/Hydra/_logs/E0/baseline1.log` and `baseline2.log`); the loaders work with an empty `dt_*.py`
set. Exit codes verified.

**Y0a (Hydralysis, M): durable IO.** Goal: 4.1.
Files: new `durable.py`; `backends.py` (`write_json`); `workcopy.py` (only `_save_store`, `load_store`);
`targets.py` (`register`); `overlayjobs.py` (job record writes); new `tests/test_durable.py`;
`tests/test_address_maps.py` and `tests/test_query.py` (one line each, 8.1).
Depends on: none. Parallel with: E0, Y0b-d.
Surface: none. Ships in 0.5.x against hydra.2/3.
Tests: torn, zero-length, mis-sealed and missing-with-`.bak` files each return the old or new content,
never empty-as-no-edits; the `AppendLog` tests of 4.1 item 3 (CRC-32 from `zlib.crc32`; a cut at every
offset of the last line, then a repairing append; mid-log corruption refused by reader and writer; a
crash inside the repair); `PermissionError` retry through a monkeypatched replace; the grep gate; v2
store loads. Fault: kill a writer process between tmp write and replace (`durable.fault`).
Acceptance: `store_corrupt` raised, not "start empty"; no record-bearing write outside `durable`.

**Y0b (Hydralysis, S): client retry policy and `EngineError`.** Files: `hydra.py` (retry only
idempotent commands after `closed`, `details.ambiguous`; widened `EngineError`; `Engine.capabilities()`
returning `{}` on protocol 2), `tests/fakehydra.py` (connection drop after a mutating call; busy with
holderInfo), `tests/test_client.py`. Review follow-ups (the `next` exemption from the list cap, the
`unittest.main()` guard) are Y0e's (8.2). Surface: none. Tests: a dropped `apply_overlays` reply is not
re-sent and the marker reconciles; reads are retried. Acceptance: no mutating call is blindly re-sent.

**Y0c (Hydralysis, S): fast/engine pools.** Files: `mcp.py`, `tests/test_mcp_transport.py`.
Tests: four blocked engine calls do not delay `fingerprint` or `disasm`. Acceptance: `MAX_OUTSTANDING`
still answers `busy` with a retry hint. **`MAX_OUTSTANDING` is per lane** (7.6): 8 on the engine pool and
8 on the fast pool, so the total outstanding can reach 16; the hint is text (`retryAfterMs=2000` in the
message) until the engine's structured `busy` exists.

**Y0d (Hydralysis, S): the one catalog epoch.** Files: `api.py` (`backend.action += doctor, backups`;
`options` bag on `backend`, `ghidra_run`, `job`; pass-through to stub handlers returning
`not_available`), `workflow_help.py`, `tests/test_contracts.py` (catalog hash, `CATALOG_EPOCH`).
Acceptance: **`backend action=status` and `backend help`** report `catalog:{epoch, hash}` (and nothing
else does, 7.7); changing the tool table without bumping the epoch fails the test (the hash covers the
tool table only, not `instructions()` or the help output). Later packages never edit the schema. A
non-empty `ghidra_run` or `job` `options` bag answers `not_available` until its handler is registered
(8.2); `cli.py` exposure is Y0e's.

### W1

**Y0e (Hydralysis, S): W0 review follow-ups.** Goal: the work that the W0 reviews found but no W0 package
could own (8.2). Files: `durable.py` (log reads streamed, no `localio` budget; the every-acquisition tail
check with the size comparison; 4.1 item 3), `tests/test_durable.py` (the two-process test of 4.1 and a
log larger than 32 MiB), `hydra.py` (`write_daemon_config` through `durable.atomic_write` without a seal;
the `EngineError` cap exempts `next`), `tests/test_client.py` (the `unittest.main()` guard at the end),
`cli.py` (`backend` `doctor` and `backups` actions and `--options` pass-through), `runtime.py` and
`runtime_worker.py` (`_write` through `durable.write_json`). Depends on: Y0a, Y0b, Y0d. Parallel with: P1a,
E1, Y1. Surface: none. Tests: those named above, plus the write-gate ratchet of `tests/test_durable.py`
updated for the sites that now go through `durable`. Acceptance: the full unit suite green; the AST gate
lists no record-bearing writer outside `durable` except the artifact writes of 8.2.

**E1 (Hydra, M): negotiation, identity, error contract, `expect`, `rk`, and the seams.**
Goal: everything the other engine packages build on, with no behaviour change for protocol 2.
Files (8.1): `S/Session.java` (hello negotiation, `info(c)` rendering capabilities, limits and policy from
`Advertised`; the status header; **the `admit` call at `:248` passes the request** and **the call
sites of `ProjectEntry.info(client)` at `:265`, `:333`, `:427` pass the client**; the `case` dispatch
otherwise untouched), `S/Scheduler.java` (only signatures: `laneOf(cmd, req, v3)`, `admit(c, cmd, req, m, waitMs)`
and the `describe(boolean)` overload, all returning today's values), `S/ImportCommands.java` (the
`admit` call at `:112` only), `S/ProjectCommands.java` (the call sites of `ProjectEntry.info(client)` at
`:92` and `:395`), `S/ProjectEntry.java` (the `info(Client)` signature, same value),
`S/UpgradeCache.java` (`currentDbVersion()` moved out, `CURRENT_DB_VERSION` now `DbVersions.program()`),
`S/HydraInfo.java`, `S/HeadlessSession.java` (endpoint and `ready`: `protocolMin/Max`; `paths` set at
start; the generic `-set key=value` flag), `S/Client.java` (`protocol`, `v3()`: written once by the first
`hello`, 3.1), `S/SessionException.java` (all new codes, the `next` and `retryAfterMs` carriers, and the
one busy-details and the one `bad_request`-details helper, conditionals C12 and C13),
`S/Connection.java` (`error()` takes the client and emits `next` and `retryAfterMs` for v3, C10),
`S/Operations.java` (`expect` on signature, data_type, v3 only), `S/EditCommands.java` (`withLastEditor`
fields, `rk`, v3 only), `S/Journal.java` (`rk`); new `S/Identity.java` (paths, platform,
analysisIdentity, cached decompiler hash), `S/Advertised.java` (capability, limit and policy names
declared up front), `S/Settings.java`, `S/Preflight.java`, `S/DbVersions.java` (`program()` and a
`dataTypes()` that returns `null`; D31, 3.1, 3.2, 3.5, 3.7).
Depends on: E0 and P1a (its `cc_e1.py` runs on P1a's loader and vendored 1.0.0 client). Parallel with: Y1, Y0e.
Surface: hello block (3.2), endpoint fields, `expect`/`rk` (3.4), `next`/`retryAfterMs`.
Tests: `examples/char_e1.py` new goldens (hello at protocol 3 with `paths`, `platform` and
`analysisIdentity` masked and `capabilities`, `limits` and `policy` compared as required subsets, 3.1; `expect` conflicts on signature and data_type
with the same key order as rename; `rk` replay with the reconstructed reply of 3.4);
`examples/contract_tests.py` (a protocol-2 hello is answered byte-identically to the committed shape;
endpoint `protocol:2` + `protocolMax:3`; a request for 9 is answered 3; absent 2; registering an unknown
capability, limit or policy name throws; the first `hello` fixes the protocol: a second `hello` asking 3 on
a protocol-2 connection answers 2, `"protocol":"3"` answers 2); `examples/cc_e1.py` (V6 first: the
vendored 1.0.0 client against the E1 engine connects and works, endpoint `protocol:2`; then G1 and the `rk`
half of G7 on the stock 1.0.0 client: a v2 `edit` with a wrong `expect` on `signature` and on `data_type`
succeeds, a v2 request with the same `rk` twice is applied twice); a seam test that `laneOf(cmd, req, v3)` and `describe(false)` return exactly today's
values for every command and that the `-set` flag reaches `Settings`.
Acceptance: seven old scenarios `identical` at protocol 2; the new goldens differ from nothing else;
`dbVersions.program` non-null and equal to the constant; after E1 alone no engine behaviour differs
at protocol 2.

**P1a (Hydra, S): client library protocol range and the protocol-2 compatibility harness.** Files:
`support/ghidra_session.py` (`PROTOCOL=3`, `PROTOCOL_MIN=2`, `check_compatible`, endpoint overlap,
`session.protocol`; the pass-through of a `config.json` `engine` object as `-set key=value`, 3.7), new
`examples/client_compat_tests.py` (with the loader for `cc_*.py`, 5.1), new
`examples/stock/ghidra_session_1_0_0.py` (the 1.0.0 client at `b6df709e1e`, vendored byte for byte, so
that the protocol-2 behaviour tests really are a protocol-2 client). Surface: client side of 3.1. Tests:
the 1.1.0 client against a fake protocol-2 server and against the real hydra.3 install (works at 2);
against the hydra.4 candidate (3); an engine that sends `protocolMax` below 2 is refused with both versions
named. P1a needs no engine of E1 to pass: the vendored 1.0.0 client against the E1 engine (V6) is the
first test of E1's `cc_e1.py`. Depends on: none; **lands first in W1**, because every `cc_*` file of
every later engine package (E1, E2, E3a, E3b, E4, E5) runs on its loader and its vendored client.
Acceptance: all pass; the 1.1.0 client works at 2 against hydra.3 and at 3 against the E1 engine.

**Y1 (Hydralysis, L): store v3, effects, bundles.**
Files: `workcopy.py` (v3 load/migrate/save **read with `require_seal=True`**, effects capture in
`edit`, `pending_of(store)` and the extended marker of 4.2 in `state_of` and `_prefix_matches`, the
`commits[]`/`archived[]` schema, `revert` with `has_dependents` and `cascade`, `has_overlays` and
`expected_state` through `durable.exists` so that the `.bak` fallback applies, 8.2),
`revisions.py` (effect and field vocabulary), `analysis.py` (new kinds, option validation; the legacy
`save_overlay` is deleted, 8.2),
`scripts/RusticQuery.java` (`effects` output, `annotation_probe`, `verify_before` in `apply_overlays`, and
`state:null` to clear the `overlay_state` option, 4.6 step 5),
`query.py` (`status options.show=changes`), new `annotations.py` (bundles), new
`tests/test_store_v3.py`, `tests/test_bundles.py`, `tests/test_engine_integration.py` (real-engine round
trip, env-gated), and the existing tests that write a store by hand (8).
Depends on: Y0a. Parallel with: E1, P1a, Y0e.
Surface: store v3 (4.2), bundle format (4.9), `changes`.
Tests: v2 to v3 migration is lossless and leaves `.v2.bak`; effects round trip for rename, comment,
signature, type, label, variable, struct; `before_unknown` handling; subject rebase tests unchanged;
bundle export then dry-run import on a fresh target reports hash, sha256 and base drift; the replay set
with a committed subset and a skipped record **below** a committed one (the skipped record is pending and
replayed, never taken for committed; the marker of a program built before the commit no longer matches).
`revert` of the earlier record of a chain is refused with `has_dependents`, `cascade` removes the chain, a
batch reverts whole (4.2); a hand-stripped seal on a v3 store is `store_corrupt`; with the main store file
deleted and the `.bak` intact, `has_overlays` and `expected_state` still see the overlays. Golden: a
RusticQuery `effects` output check on the committed MSVC fixtures. Fault: kill between engine apply and
store write (the marker heals it).
Acceptance: all existing rebase tests green; `verify_before` mismatch rolls the whole transaction back and
names the effect.

### W2

**E2 (Hydra, L): format, backup, gate, fork report.**
Files (8.1): new `S/ProjectFormat.java`, `S/ProjectBackup.java` (with the canonical serializer of 3.4);
`S/UpgradeCache.java` (`readStored`, no behaviour change; the DB-version constant is already
`DbVersions`, E1), `S/ForkCommands.java` and `S/ProjectFork.java` (purpose, open, verify, cost, warnings,
sidecar fields `purpose` and `disposable`, one validation method also registered with `Preflight`),
`S/ProgramCommands.java` (`openWritable` gate, `upgradeBackup`), `S/EditCommands.java` (`save` comment
stamp), `S/ProjectCommands.java` (`openProject`) and `S/ProjectEntry.java` (`info(client)` adds `format` for
v3, the one conditional C6), `S/DbVersions.java` (`dataTypes()`: the data type database version read from
a database header, tested against 12.1.4 data or left `null`); new `format-matrix.json`, `examples/format_gate.py`, `examples/make_legacy_fixture.py`
(builds a small 12.1.4-format project from one of our own generated PEs with stock 12.1.4; the output
is committed; it contains nothing derived from a game), `examples/vectors/canonical-manifest.json`,
`examples/dt_e2.py`, `examples/char_e2.py`, `examples/cc_e2.py`. **E2 does not edit `Session.java`**
(E1 placed the `ProjectEntry.info(client)` call sites) **and names no lane**: a backup reaches the `maint`
lane through E3a's command mapping, with no dependency between the two packages.
Depends on: E1 (and, for `cc_e2.py`, P1a). Parallel with: E3a, Y2.
Surface: `format`, `fork_project` fields and manifest, gate, `backup_required` (3.4).
Tests: characterization `format_fork` (format on a current-format fixture; a backup fork; sidecar and
manifest masked, key order checked); `daemon_tests` `upgrade_gate` (needs `--legacy-project`: canonical
`upgrade:true` without `backup` gives `backup_required`; stale, unverified, foreign-revision, wrong self-hash
or wrong-size backup is refused; a good one opens; a fork and the upgrade cache are exempt, and so is a
fork whose sidecar has no `disposable` field (a hydra.2/3 fork); a generation or a project with a missing,
unparseable or `disposable:false` sidecar is canonical; source tree hash unchanged on read-only paths),
`format_readonly` (tree hash before and after), `backup_fault` (kill the daemon mid-backup: no folder with a
verifying manifest, retry succeeds; corrupt one byte: client re-hash refuses; engine gate still passes by
design, which the test documents; a failed `verify` leaves no project in the destination and no manifest,
3.4), `fork_report` (NTFS asserts `method:"copy"` and a warning; **on the Dev Drive (ReFS) it also asserts that
a freshly forked candidate has the same `Revision.of` as its source**, the property that the step 4 gate
of 4.6, `backup.source.revision == Revision.of(candidate)`, relies on and that the NTFS check of the
second review did not cover), `manifest_canonical` (the vector of 3.4,
a non-ASCII path and U+2028 written by the engine and verified by Python and the reverse),
`cc_e2.py` (G7 `purpose`/`open` ignored for v2, G8 and V1: v2 `conflict` with `reason:"backup_required"`,
V7 the sidecar fields). `format_gate.py` fails when `ProgramDB.DB_VERSION`, `DataTypeManagerDB.DB_VERSION`,
`DataTypeArchiveDB.DB_VERSION`, `ProgramUserDataDB.DB_VERSION` or `SlaFormat.FORMAT_VERSION` differ from
`format-matrix.json` (values on the sync branch: 33, 3, 5, 1, 4).
Acceptance: as the tests; old goldens identical at protocol 2; the data-type DB read is either tested
against the fixture or reported `null`.

**E3a (Hydra, L): lanes, fair key, queue info, import wait, validate-before-wait.**
Files (8.1): `S/Scheduler.java` (the bodies behind E1's signatures: MAINT, fair key, per-key cap, queue info,
ETA, history, the `Preflight` call), `S/ImportCommands.java` (remaining wait; the `ImportGate.enter` call at `:100` passes the client),
**`S/ImportGate.java`** (`enter` takes the `Client`, its `Entry` keeps it, and `queueInfo(e)` adds
`estimateScope:"load"` for a v3 entry; the `queue` object of an import wait is v2 behaviour and
stays, 3.5), `S/Requests.java` (the generic `Preflight` checks, registered under `*`), `S/Connection.java` (`respond`: the `queue` header),
`S/RequestMonitor.java` (carriers for the queue information, the **lane** and the **lane note** the
decision produced: E4 only copies them into the `script` reply), `examples/dt_e3a.py`,
`examples/char_e3a.py`, `examples/cc_e3a.py`. **E3a does not edit `Session.java`.** Every v3 effect is
gated on `Client.v3()` (3.1, 5.1).
Depends on: E1 (and P1a for `cc_e3a.py`). Parallel with: E2, Y2.
Surface: `lane`, `maint`, `queue`, `busy` details (3.5).
Tests: `lane_starvation` now passes (p99 bound recorded from the E0 baseline, not assumed), `maint_lane`
(`fork_project`/`save` start while long is saturated, on a v3 connection), `fair_key` (two labels on one
connection share; the cap holds only while another key waits), `queue_info` (position, ETA null without
history, `estimate:true`), `import_wait`, `preflight_wait` (a bad request fails at once when the lane is
full and keeps its old error order when it is not), `per_key_cap_conserving` (maint with 4 slots and two
keys that each run one request and queue another: both queued requests run, no slot idles, 3.5). Characterization: `status.scheduler` v3 shape new
golden. `cc_e3a` (the stock 1.0.0 client, hydra.3 behaviour recorded first): `v2_lane_unchanged` (G2),
`v2_queue_order` (G3), `v2_no_preflight` (G4), `v2_progress_keys` (G5: the exact key set of every
progress event during a slot wait and an import wait: the import wait still carries `queue` and gains no
`estimateScope`), `import_wait` and `import_wait_explicit` on a v2 connection (V2, both directions).
Acceptance: old goldens identical at protocol 2; golden decompile diff identical (gate 9.1, run here).

**Y2 (Hydralysis, L): lineage, commit, revert, backups on hydra.2/3, shared base.**
Files: new `lineage.py`, `commits.py`, `backups.py`; `targets.py` (stable key, `CURRENT.log` resolve),
`workcopy.py` (shared base key, `pending`, `stale`, `_directory`, clearing a stale `overlay_state` on a
fresh generation base), `overlayjobs.py` (kind `commit`), `exporting.py` (header, resume refusal), `query.py`
(`stop`, `status options.show=lineage`), `api.py` (**the handler registry** that replaces the Y0d stubs: it
imports the handler modules of the later packages lazily and answers `not_available` for a module that
does not exist yet; 8, 8.2), `tests/fakehydra.py` (fork purposes), new `tests/test_lineage.py`, `tests/test_commit.py`, `tests/vectors/canonical-manifest.json`
(a copy of E2's vector, asserted byte-identical at the release gate 9.8), `tests/test_engine_integration.py`
additions. `backups.py` registers `backend action=backups` (`op=list|verify`) and `commits.py` registers the
`job` `options` filters (`kind`, `cid`), so that no later package edits `api.py`.
Depends on: Y1, Y0a, Y0b (`tests/fakehydra.py`), Y0d (`api.py`) and Y0e (the `AppendLog` it builds the
logs on). Parallel with: E2, E3a.
Surface: 4.4-4.7.
Tests: key stability across a generation flip (the overlay store is found); commit preconditions;
`dry_run` has zero side effects (tree hash); a commit on a KotOR-sized fixture produces a verified
generation and an untouched master; revert; one-way confirmation required when format unknown; torn and
gapped `CURRENT.log`; `tampered` detection; **subset and skip commits** (4.2: dependency closure,
`selection_not_closed`, skip propagation, a skipped record below a committed one stays pending and is
replayed by the next sync and taken by the next commit, revert of a commit makes its ids pending again;
`revert_chain`: commit c1, commit c2, `commit_revert` c2 then c1, the records of both are pending again in
`seq` order (c1's rehydrated from its archive) and the pointer is back at generation 0; `subset_missing_type`:
a subset commit of a signature without the struct it uses ends `ABORTED` with the effect named and nothing
published, or the test fails and the closure is extended (4.2); a `batch` split by `only` is refused or
completed by the closure);
**archival** (the previous commit's records leave `edits[]`, the caps then bound the live records);
the **reference snapshot** (a commit while edits continue compares against the `upTo` texts, and a
function touched by an outside record is `excluded`); the generation's sidecar rewrite on hydra.2/3 and
that a fork of the generation carries no `overlay_state`. Fault matrix: every point of 4.6, including
`publish_torn` followed by a successful new commit, `intent_torn` and the subset variants, **and the
two-process torn-tail test of 4.1 on `CURRENT.log`** (a long-lived process appends again after a second
process was killed mid-line), with oracle O1-O6, fresh roots. Golden: **commit round trip** (after-commit touched functions against the
reference snapshot; its own comparison, never mixed with the hydra.3/hydra.4 diff).
Acceptance: all O1-O6 hold at every fault point; two simultaneous commits give one `commit_busy`.

### W3

**E3b (Hydra, L): cancel-aware waits, bounded release, abandoned holders, `applied`.**
Files (8.1): new `S/Waits.java` (the single timed `tryLock` and the registration state machine of 3.5);
`S/RequestMonitor.java` (the wait registration and the `cancel()` override), `S/Caller.java` (monitor in
the thread local), `S/Access.java`, `S/ProgramEntry.java` (waiters, `abandoned`), `S/OverlayCommands.java`
(lock site only), `S/Connection.java` (`run`: grace, `shutdownNow`, disconnect regardless), `S/Session.java`
(`disconnect`, optional orphan TTL in `reap`), `S/ProjectCommands.java` (`leaveProject`),
`S/ProgramCommands.java` (`releaseUse`, `closeEntry`); `examples/dt_e3b.py`, `examples/cc_e3b.py`.
Out of scope, stated: the untimed overlay-lifecycle `lock()` calls of `OverlayCommands.java` (3.5, 6).
Depends on: E3a, **E2** (it edits `ProgramCommands.java` and `ProjectCommands.java` after E2 did) and P1a
(`cc_e3b.py`). Parallel with: Y3.
Surface: `cancelled.details.applied`, `busy.reason`, `abandonedRequests`, `lock_queue_full`.
Tests: `cancel_queued` (slot wait and lock wait answer `cancelled` within 1 s), `dead_client_lock_wait`
(kill a client blocked in `wait=3600000`: released within `cleanupGraceS + abandonWaitS + 2 s` for a
cooperative script), `abandoned_holder` (a deliberately non-cooperative script: `abandonedRequests`,
`busy{reason:abandoned}`, the program is not disposed, `health` lists it, nothing waits 10 minutes),
`lock_queue_full`, `applied_flag`, and the three tests of 3.5: **`writer_vs_steady_readers`** (an
exclusive request against steady shared readers acquires within a bounded time and keeps its FIFO
position; run first against a slice-polling build, where it must fail), **`cancel_while_waiting`**
(including 200 cancels raced against the release, no leaked lock and no stray interrupt) and
`deadline_in_lock_wait`. `cc_e3b` (the stock 1.0.0 client): `dead_client_lock_wait` (V3),
`abandoned_holder` (V4: `busy` with the existing keys), `cancel_while_waiting` (V5). Characterization
unchanged at protocol 2.
Acceptance: the ownership-bits question (3.5) is decided in review and recorded; golden diff identical.

**Y3 (Hydralysis, M): rebase, publish, merge.** Files: new `views.py`; `workcopy.py`, `query.py`,
`tests/test_views.py`. Depends on: Y2. Surface: 4.7-4.8. Tests: stale-after-commit; rebase outcomes
clean, converged, conflict, and "already in the master" decided from the generation manifests' `store.ids`
(a record published from another view matches by `merged_from`); publish idempotent through `published_through`; `stale_view` refusal with
`next`. Acceptance: no conflict outcome is silently resolved.

### W4

**E4 (Hydra, M): script isolation.** Files: `S/ScriptCommands.java` (`isolation`, `scriptSha256`,
`attemptedChanges` measured before the rollback, `basedOn`, and the `lane` and `laneNote` **copied from the
request monitor**, where E3a stored the decision; E4 does not decide a lane; the `script` validation
method registered with `Preflight`), `S/OverlayCommands.java` (`loadOverlay` extracted), new
`S/PrivateInstance.java`; `examples/dt_e4.py`, `examples/char_e4.py`, `examples/cc_e4.py`.
Depends on: E3b (and, through it, E3a, E2) and P1a (`cc_e4.py`). Parallel with: E5, P1b.
Surface: 3.4 `script`, 3.6.
Tests: a mutating user script with a concurrent decompile reader in each mode (shared: attempted and
rolled back; exclusive and private: readers never see it); the master file hash and revision unchanged;
RusticQuery read actions report `attemptedChanges:false`; `script_changed`; `unsavedIgnored` when the
program holds unsaved edits; **the private open cost on KotOR is measured and written to the test
timings**; the `Program.lock` spike result recorded either way. `cc_e4`: a v2 `script` with `isolation`,
`lane` and a wrong `scriptSha256` runs as today (G7). Golden decompile diff identical.
Acceptance: `shared` unchanged for protocol 2.

**E5 (Hydra, M): health and watchdog.** Files: `S/Session.java` (`isInline`, `case health`, starting the
watchdog), new `S/Health.java`, `S/Watchdog.java`, `S/Scheduler.java` (`describe` with `tryLock` for v3,
lane stats), `S/HeadlessSession.java` (parse `testHooks`); `examples/dt_e5.py`, `examples/cc_e5.py`.
Depends on: E3b (lane stats) and P1a (`cc_e5.py`). Parallel with: E4, P1b.
Surface: `health` (3.4), `debug_stall` behind the launch property.
Tests: `health` answers while a long request runs; a daemon suspended from outside (`NtSuspendProcess`)
is seen by the Python probe as a live pid with no answer; with the hook, `tick.ageMs` grows and
`schedulerLockOk` is false while `ping` still answers; a v3 `status` no longer blocks on a held
scheduler lock (`cc_e5`: the same held lock makes a v2 `status` block as on hydra.3, G6);
`hello.platform.testHooks` true and `health.state:"degraded"` with the hook on.
Acceptance: the hook cannot be enabled from `config.json` or a request.

**P1b (Hydra, M): launcher.** Files: `support/ghidra_session.py` (deadline, `LaunchError`, registry,
`DuplicateDaemonError`, `Daemon.health()`, `Daemon.attach()`), `examples/dt_p1b.py`. Depends on: P1a.
Tests: `launch_errors` (no JDK, JDK 21 against 25, heap above free RAM, lock held, early exit: each a code
and details), `duplicate_daemon` (a second state dir with `singleton:"per-install"` raises; the default
warns), `call_deadline` (a hung call cancels and raises `deadline_exceeded`, the connection survives),
N concurrent launchers start exactly one daemon per root. Fresh roots only. The deadline exists only in
the library that ships with hydra.4 (3.8); against a hydra.2/3 engine Hydralysis uses the client-side
watchdog of 7.6 (Y4a).

### W5

**E6 (Hydra, M): soak harness.** Files: new `examples/soak_tests.py`. Depends on: E2, E3a, E3b, E4, E5. R1
follows it in W5.
12 client processes with distinct labels over mixed work (quick decompiles, quick scripts, long sleeps,
fork and save, cancels), seeded client kills. Pass criteria: no lost, duplicated or reordered
acknowledged edit against the clients' own logs; every queue empty and no program owner left after the
clients exit; quick-lane p99 under the bound recorded by E0 on hydra.3; no `abandoned` holder after
cooperative scripts; **a backup (`fork_project purpose:"backup"`) started while the long lane is
saturated runs in the `maint` lane** (the combined check of E2 and E3a, which share no code). PR lane
about 2 minutes; nightly longer.

**R1 (both, M): hydra.4 release preparation.**
Files: Hydra: `S/HydraInfo.java` (version), `CHANGELOG.md`, `README.md` (a protocol 3 section pointing here;
the new limits and the config keys of 3.7; the "Protocols" matrix), `ARCHITECTURE.md` (rows for the new
classes), `certification.manifest` (its own release entries; every package appends its own files, 8), the
release workflow (a dry run); Hydralysis: new `tools/bump_hydra.py`. The **release notes** carry the items
of 5.2 (D4 `minClient` unchanged, the pin refusal of Hydralysis 0.4.x, V1 to V7 by name) and the full v3 hello
golden. `tools/bump_hydra.py` generates `RELEASE`, `ASSETS` with SHA-256 and sizes and the `fakehydra`
constants; **R1 is its only owner**, Y4a runs it. **No tag, no push, no release by this stream**; the tag is an
owner action. Until then Hydralysis tests run against the candidate install with `hydra_allow_unpinned`.
Depends on: every engine package, **including E6** (R1 runs after E6 within W5).

### W6

**Y4a (Hydralysis, L): engine adoption and supervisor.** Files: `hydra.py` (capabilities, pin,
`Supervisor`, deadlines: P1b's on hydra.4, the half-close and abandon helper of 7.6 on hydra.2/3), `query.py`
(lane hint, shorter waits), `tests/fakehydra.py` (v3 fake: queue info, `next`, health). It **runs** R1's
`tools/bump_hydra.py` to produce the pin bump and owns the files the script edits; it does not own the
script. Depends on: R1, Y0b, **Y2** (`tests/fakehydra.py`) and **Y1, Y2, Y3** (`query.py`). Tests: the
deadline helper of 7.6 (half-close and abandon, never `close()`) against the fake and the real hydra.3 (the
cases L, S, C of 7.6 and the abandoned-connection cap); 7.2 policy against the fake and
the real engine (a suspended daemon is restarted within budget; `lost_on_restart` recorded; a slow daemon
with non-recoverable unsaved edits is not restarted); degrade matrix 7.5 against hydra.3.

**Y4b (Hydralysis, M): doctor.** Files: new `doctor.py` (it registers `backend action=doctor` with the
handler registry that Y2 built and does not touch the dispatcher file, 8.2), `tests/test_doctor.py`. Depends on: P1b, E5, Y2 (the registry). The doctor reports leftover `*.tmp` files and abandoned connections (7.6).
Tests: zero daemon spawns and zero engine calls when no daemon exists; cites `hello.paths/platform/
analysisIdentity`; one finding per section of 7.1.

**Y4d (Hydralysis, M): engine backup and format adoption.** Files: `commits.py`, `backups.py`,
`lineage.py`. Depends on: E2, Y2. Switch backups to `purpose:"backup"` (`writer:"engine"`), use
`format` for the confirmation, pass `backup:` to the candidate open. Tests: a Python-written backup is
accepted by the engine gate and the reverse; fault matrix re-run.

**Y4e (Hydralysis, S): `ghidra_run` modes.** Files: `userscripts.py`, `tests/test_query_script.py`.
Depends on: E4, Y2 (the handler registry: it registers the `ghidra_run` `options` handler from
`userscripts.py` and does not touch the dispatcher file). Tests: `private` only on a clean working copy, `exclusive`
otherwise; the reply shows `attemptedChanges`, `isolation`, `basedOn`.

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
| 9.1 | **Golden decompile diff**, hydra.3 against the hydra.4 candidate | `tools/golden.py capture` then `diff` on fresh **copies** of KotOR (program pinned by SHA-256, function count read from the engine, not hard-coded: the 8616 seen on 2026-10-27 is an observation) on **both** paths, `production` (RusticQuery, the path agents use) and `explicit`; plus the **8 public MSVC fixture programs, 4 x86 and 4 x64** (`flow`, `vcall`, `diff1` and `diff2` for each architecture; `D:/Projects/Hydra/_golden/sets/fixtures.json` lists exactly these eight, and an earlier report of "6 x86 and 4 x64" is wrong), profile `fixtures`. Their function counts are read from the engine like KotOR's: the set file totals 4,497 functions while `docs/golden-harness.md:143` says 3,959, a difference this gate does not depend on and does not resolve. Identical on all (hydra.3 against itself is deterministic: 8616 identical). Source tree hash before and after each capture equal. Run after E1 (the seams must change nothing), after E3a, after E4, and at release. Any difference blocks. The hydra.2-to-hydra.3 difference (one x64 `strncmp` function per fixture, GP-7212) is **not** in this comparison. |
| 9.2 | **Commit round trip** (separate comparison, never mixed with 9.1) | After a commit on the KotOR copy, the touched functions of the new generation decompile identically to the working copy; 25 untouched functions identical to the previous generation. |
| 9.3 | **Characterization** | the seven scenarios `identical` at `--protocol 2`; the v3 run is always made with `--require-v3` (without it an engine that serves no v3 is a SKIP with exit 0, which E0's review found and which a gate must not accept); every v3 scenario golden recorded, reviewed as a diff of additions, committed; the full v3 hello golden recorded by R1 (3.1) |
| 9.4 | **Engine suites** | `session_smoke.py`, `contract_tests.py`, `daemon_tests.py` (all, with `--legacy-project`, so `legacy_overlay` and the older-format half of `upgrade_cache` run: the sync stream skipped them), `client_compat_tests.py` (with every `cc_*.py`: the protocol-2 behaviour tests of 5.1, run by the stock 1.0.0 client), `format_gate.py`; plus the fork tests on a ReFS volume |
| 9.5 | **Soak, 12 clients** | `soak_tests.py` PR lane green; one nightly-length run recorded (E6 criteria) |
| 9.6 | **Upgrade and backup round trip** on the legacy fixture | backup (engine) then gate refusal without it, success with it, on a fork; commit to a new generation; restore the backup alongside; the restored tree hash equals the original; stock Ghidra 12.1.4 opens the restored backup read-only and does **not** open the committed generation (the documented one-way step, shown rather than asserted); source tree hash unchanged throughout |
| 9.7 | **DB-version check** | `format_gate.py` exit 0: the constants (`ProgramDB` 33, `DataTypeManagerDB` 3, `DataTypeArchiveDB` 5, `ProgramUserDataDB` 1, `SlaFormat` 4 on the sync branch) equal `format-matrix.json`; `hello.analysisIdentity.dbVersions` equal them at runtime and are not `-1`. A changed constant without a matrix entry and release note fails the merge, and also fails any future upstream sync |
| 9.8 | **Compatibility** | a raw protocol-2 transcript against hydra.4; the 1.1.0 client against hydra.3 (real install) and a fake protocol-2 server; Hydralysis 0.5.x test suite against hydra.3 (degraded set) and hydra.4; `bump_hydra.py` output verified against the zip SHA-256; the two copies of `canonical-manifest.json` (engine and Hydralysis) are byte-identical and both languages verify the other's manifest (3.4) |
| 9.9 | **Fault matrices** | Hydralysis commit points (4.6) with oracle O1-O6; engine `backup_fault`; Y0a torn and zero-length files; all green |
| 9.10 | **Measurements recorded before any constant is fixed** | fsync latency per volume (F: Dev Drive on USB NVMe, C:, D:, E: HDD); store write cost at 1, 4, 16 writers, **including `write_json` of job and progress records, which now does a read, a `.bak` write and a main write (two fsyncs, two replaces: about 16 ms per 600-byte record on D: in Y0a's review, unmeasured on F:, C: and E:) and is rewritten often by export workers**; backup hash throughput; clone against copy on KotOR (122 MB) with the 1.5 GB program as a stress case only; private-instance open cost on KotOR; quick-lane p99 with the long lane saturated, before and after; the per-phase named-view cost. `quickScriptMaxS`, grace times, ETA budgets, `SYNC_LOCK_S`, copy limits and the private default derive from these |
| 9.11 | **Hygiene** | every commit authored and committed as `KelpHect <kellhect@gmail.com>` (checked with `git log --format='%an <%ae> | %cn <%ce>'`); `certification.manifest` lists every new file and `buildHeadless` passes the IP check; docs state every limit of section 6; `examples/check_ownership.py` passes for every package branch (8.1) |

## 10. Open owner decisions

Only the choices that are genuinely the owner's. Each has the default this design assumes if no answer
comes, and what it blocks.

| # | Decision | Default | Blocks |
|---|---|---|---|
| OD1 | **Backup policy.** Add a second, independent copy by default (for example `E:\dev-cold\...`, a full copy), `backup_min_independent` 1 instead of 0, and who authorises the 50 GB threshold behaviour? A same-volume clone does not survive loss of the volume. | One primary clone, `min_independent` 0, second root opt-in, ask before any copy over 50 GB | Y2 config defaults, Y4d |
| OD2 | **Generation mode against the Ghidra GUI.** The GUI opening the original `.gpr` sees none of the committed annotations. Provide a "materialise current generation" action (a COW clone to a path you choose) in Hydralysis, and keep in-place replace permanently out? | Add materialise later (not in this plan); in-place never | the 0.5.0 documentation wording |
| OD3 | **Daemon singleton and the two live daemons** (18220 `default` at `F:\dev-cache\hydra-state`, 17936 `rusticre` at `F:\dev-cache\rusticre-latest`): consolidate into one root and enforce `singleton:"per-install"`? Changing the instance id or state dir starts a second daemon, so a Hydralysis rename of `INSTANCE` must wait. | Warn only; no consolidation by this stream | P1b default policy |
| OD4 | **Supervisor default.** Auto-restart on dead or wedged daemons within the 3-per-10-minutes budget, refusing while non-recoverable unsaved edits exist? | On, as 7.2 | Y4a default |
| OD5 | **Tag and publish hydra.4 and pin Hydralysis to it** (and the visibility of the private Hydralysis repo). This stream creates no tag, release, push or PR. | Not done | R1 follow-up, Y4a |
| OD6 | **Legacy window.** hydra.4 and hydra.5 serve protocol 2; refuse it from hydra.6? | Review at hydra.5 | none now |
| OD7 | **Per-agent default views and the agent identity** (`options.as`, replacing `rusticre:<pid>`): when, and who may commit when ten agents run (any holder of the confirmation, one integrator identity, or a human-approved flow)? | Not before Y5's preconditions; any caller may commit with the confirmation | Y5 |

Decided here rather than asked (veto by saying so): `minClient` stays 1.0.0 (D4; it is also a required
line of the release notes, 5.2); `save` is in the maint lane for v3 connections (D16, 5.1); no inference of the quick lane (D16); commit and publish ride `type_edit` kinds (D25); no
automatic deletion (D28).

---

## Appendix A: code facts and where they were read

Branch `feat/session-extract` @ `b6df709e1e` (Hydra) and `feat/hydralysis-0.5` @ `d0466bc` (Hydralysis).

| Fact | Where |
|---|---|
| Inline commands are `ping`, `cancel`, `status`; a **repeat** `hello` is not inline (the first `hello` of a connection is answered synchronously by `Connection.authenticate`, `Connection.java:187-205`); admit happens before the command runs | `Session.java:219-221`, `:223-250` |
| `Session.info()` builds both hello and the status header; `PROTOCOL_VERSION = 2`; `CLEANUP_WAIT_MS = 600_000` | `Session.java:319-337`, `:51-52` |
| `disconnect` cancels, then `leaveProject(c, p, true, CLEANUP_WAIT_MS)` | `Session.java:109-129` |
| `reap` uses non-blocking `tryLock` on the project and program | `Session.java:167-214` |
| `laneOf(String cmd)`: `script`, `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay` are LONG; the queue is keyed by `c.id`; `m.waiting(lane + " slot")` has no queue info; `describe()` takes `lock.lock()`; release is round-robin by client; the slot wait polls its own condition in 100 ms steps and checks cancel | `Scheduler.java:59-69`, `:84`, `:152`, `:155`, `:285-290`, `:266-277`, `:157-183` |
| `Scheduler.admit(c, cmd, m, waitMs)` has two callers: `Session.execute` (not for `import`) and `ImportCommands`; `ImportGate.enter(kind, who, clientId, project, what, bytes, m, waitMs)` receives only `c.id` (`ImportGate.java:165`, called at `ImportCommands.java:100`); the import wait already puts `queue` in progress events (`ImportGate.java:188-194`) and `status.requests[].queue` (`RequestMonitor.java:111`) in protocol 2; `Scheduler.describe()` takes no argument (`Scheduler.java:285`) | `Scheduler.java:138`, `Session.java:248`, `ImportCommands.java:100`, `:112`, `ImportGate.java:165`, `:188-194`, `RequestMonitor.java:111`, `Scheduler.java:285` |
| `Connection.run`: cancel, `awaitTermination(1, HOURS)` twice, then `session.disconnect`; `Caller.enter` in `respond`; `annotate` adds `stale`/`refreshed` | `Connection.java:93-108`, `:211-250` |
| Lock waits are one timed `tryLock(wait)` and ignore cancel; the three locks are **fair** `ReentrantReadWriteLock`s | `Access.java:105-109`, `ProgramEntry.java:191-196`, `OverlayCommands.java:142`; `ProgramEntry.java:115`, `ProjectEntry.java:43`, `Overlay.java:54` |
| `RequestMonitor.cancel()` is `TaskMonitorAdapter.cancel()` (public, overridable); the deadline timer calls it; `Session.cancel` and `Connection.run` call it | `TaskMonitorAdapter.java:123`, `RequestMonitor.java:118-121`, `Session.java:393,409`, `Connection.java:95-97` |
| `Caller.enter(Client, Identity)` stores no monitor; `scope()` exists | `Caller.java:41-50`, `:86-90` |
| `RequestMonitor.waiting(what, queueInfo)` exists and feeds progress events | `RequestMonitor.java:93-101`, `:191-193` |
| `expect` is wired for rename, label, comment; `signature` and `data_type` compute `oldSig`/`oldType` without comparing | `Operations.java:48-60`, `:157`, `:186`, `:229-271` |
| `withLastEditor` maps `name` and `comment` only; `Journal.fieldOf` returns the op name for the rest; a journal entry is a copy of the per-op result plus `seq`, `at`, `client`, `name`, `harness`, `cmd` | `EditCommands.java:49-70`, `:76-88`, `Journal.java:103-125` |
| Contained scripts: outer transaction always rolled back; `modBefore` read; `changed:false` by construction when contained; `exclusive` flag | `ScriptCommands.java:92`, `:172-196` |
| `loadOverlay` uses `getReadOnlyDomainObject` / `openReady` | `OverlayCommands.java:277-314` |
| `olderFormat` reads `DB Version` and `Language Version` without opening the program, swallows errors to `null`; `currentDbVersion()` is **private static**, returns `-1` on failure, feeds `CURRENT_DB_VERSION` | `UpgradeCache.java:986-1042`, `:1056-1065`, `:107` |
| `openWritable`: `getDomainObject(e, upgrade, false, m)` | `ProgramCommands.java:408-439` |
| `fork_project`: temp folder then move; `Revision` before and after (a changed source removes the copy); sidecar (`kind ghidra-session-fork`, no `disposable`; a failed write only warns); `writable` defaults to true; success reply has no file-system fields; refusal `cost` has them | `ForkCommands.java:54-277`, `:205-214`, `:246-257`, `:82`, `ProjectFork.java:92-179` |
| `ProjectFork.clones`: Windows and ReFS only | `ProjectFork.java:138-141` |
| `Revision.of`: size and mtime for files above `HASH_LIMIT` (1 MiB); excludes `projectState` | `Revision.java:51-80`, `UpgradeCache.java:98` |
| Import: unlimited gate wait, then `admit` and `lockProject` with the default 10 s | `ImportCommands.java:77-114`, `Requests.java:30-44` |
| Endpoint file and `ready` carry `protocol`; hydra.2 client sends `protocol` in hello and checks equality on hello and endpoint | `HeadlessSession.java:187`, `:356`; `ghidra_session.py:850-852`, `:105-125`, `:1000` |
| `Daemon.connect(start=...)`, `jvm_alive` (instance lock), `LaunchError`, `sock.settimeout(None)` | `ghidra_session.py:1004`, `:969-979`, `:89`, `:845` |
| README rules: additions need no protocol change; protocol "must be equal"; 12.1.4 program DB 32 and data type DB 2 against 33 and 3 (README line numbers are at the design branch tip, +2 after `README.md:538`) | `README.md:988-992`, `:973`, `:1003-1004` |
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
| The 317 characterization steps record replies only (no progress events, older-format projects or lock timing); none carries `expect` on `signature`/`data_type`; `hydraVersion` is masked | `examples/characterization/*.json`, `characterization_tests.py` docstring |
| Gson 2.13.2 with `disableHtmlEscaping()` still writes U+2028/U+2029 as `\u2028`/`\u2029`, control characters as lower-case `\u00xx`, and keeps insertion order (run against the jar in the hydra-3 candidate install) | `Ghidra/Framework/Generic/lib/gson-2.13.2.jar` |
| Hydralysis depends on `pefile` and `capstone` only; the 8 fixture programs of the golden set | `pyproject.toml:9-12`; `D:/Projects/Hydra/_golden/sets/fixtures.json` |
| `Engine.module()` loads the session library from the engine install; connections are keyed by role; the 1.0.0 `send`/`wait` are thread-safe and `SocketSession` waits with `settimeout(None)` | `hydra.py:229-233`, `:227`; `ghidra_session.py:681-682`, `:732-738`, `:845` |
| `SocketSession.close()` closes `_w` and `_r` before `sock.shutdown`; `wait()` holds `_read_lock` (`:748`) inside `_r.readline()` (`:753`): `close()` from a second thread hangs and sends nothing (experiment, 7.6); the hydra.2 library and the one in the hydra-3 candidate differ only in `HYDRA_RELEASE` | `ghidra_session.py:740-776`, `:866-874`; `D:/Projects/Hydra/_logs/spec-rev3/exp1_client_matrix.py` |
| `Connection.run` on EOF or reset: `leaving`, cancel every running monitor (observed: `cancelled` false to true), `awaitTermination(1, HOURS)`, no socket close and no unregister until the request threads end (observed on a real hydra.3 daemon) | `Connection.java:93-108`; `D:/Projects/Hydra/_logs/spec-rev3/exp2_engine.py`, `exp2_summary.txt` |
| Overlays have no journal; the overlay lifecycle takes untimed `lock()` calls | `OverlayCommands.java:228, 238, 251, 319, 352, 404`; no `journal` in `OverlayCommands.java` or `Overlay.java` |
| `AppendLog` at Hydralysis `589432e` reads whole logs through `localio.read_bytes` (32 MiB budget); the write gate freezes 8 record-bearing and 22 artifact write sites outside `durable.py` | `durable.py` (`AppendLog`), `localio.py:18`, `tests/test_durable.py` (`FOLLOW_UP`, `NOT_A_RECORD`) |
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
8. **A replayed commit would be applied twice** unless the replay set excludes the committed records, and a scalar watermark is not enough once a commit can take a subset or skip a drifted record: commit state is a committed-id set (D32, 4.2).
9. **`laneOf` is static and cmd-only**; the `save`-if-fast heuristic of A needs state the lane decision does not have (D16, D17).
10. **A WAL under the program write lock** (B) protects an edit path Hydralysis does not use (D5).
11. **README's own versioning rule** says additions need no protocol change; none of the designs reconciled it (D2).
12. **The stock client refuses an endpoint of protocol 3**; "old clients keep working" needed `protocol:2` plus a maximum (D3), and RusticRE 0.4.x still refuses by pin (5).
13. **`tools/bump_hydra.py` does not exist**; the designs assumed it (R1).
14. **The generation sidecar hole**: "no sidecar means canonical" exempts every generation from the second on (D12).
15. **Test files would collide**: every package wanted `daemon_tests.py` (D30).

## Revision history

**Revision 3 (answers the second independent review of revision 2 and the reviews of the W0 packages).**
Docs only; no code; one commit on `design/protocol-3`. B1, B2 and B3 below are the three blocking items of
the second review, N1 to N17 its seventeen nits (numbered in the order the review listed them), W the
findings of the W0 package reviews (Y0a to Y0d, E0) that belong to the design. Every change was checked
against the code or by experiment before the text was written. Experiments (new in this revision):
`D:/Projects/Hydra/_logs/spec-rev3/exp1_client_matrix.py`, `exp2_engine.py`, `exp3_lifecycle.py` with their
recorded output (7.6); the disjointness proof was re-run with `prove_disjoint_rev3.py` (output
`prove_disjoint_rev3_out.txt`). **Rejected: none.** Two items are fixed in part and have an owner for the
rest, both marked below (N9, N17).

| Item | Disposition | Where | Note |
|---|---|---|---|
| B1 deadline fallback on hydra.2/3 | fixed, **by experiment** | 7.6 (new sub-section), 3.8, 7.2, 7.5, D33, 3.5, 6, Appendix A, Y4a | `session.close()` hangs on the real 1.0.0 `SocketSession` (Python 3.14.7 and 3.15.0): it closes the makefiles before `shutdown`; the reviewer was right. `shutdown(SHUT_WR)` returns at once and delivers the FIN (the reviewer's `close_test2` is right that it does not wake the reader, but the FIN does reach the server). Chosen: half-close and abandon (worker thread owns `wait`, `cancel`, `SHUT_WR`, never `close()`, cap 8). On a real hydra.3 daemon the request goes on until it ends by itself (cooperative: released in 0.1 s; lock wait and non-cooperative script: until the holder or script ends); an abandoned-without-FIN connection leaks the engine-side client for good. The client never relies on an EOF coming back. P1b/E3b change this on hydra.4. N8 of revision 2 is superseded by this row |
| B2 `ImportGate.java` ownership and premise | fixed | 3.1 (C4, C5), 3.5, 5.1 G5, 8.1, W2 plan, E3a, Appendix A | `ImportGate.java` added to E3a's files and to the 8.1 matrix (W2, E3a); `ImportGate.enter` receives only `c.id` (`ImportGate.java:165`), so E3a gives it the `Client`; premise corrected: an import wait already carries `queue` in v2 progress events and `status.requests[].queue` (`ImportGate.java:188-194`, `RequestMonitor.java:111`); only the slot-wait `queue` key and `estimateScope` are new; `v2_progress_keys` kept and extended. Disjointness re-proved with `prove_disjoint_rev3.py`: 50 matrix rows, 123 (repo, wave, file) cells, no cell with two packages, no file with two owners in one wave, no dependency cycle |
| B3 torn-tail repair trigger | fixed | 4.1 item 3, 4.4, D10, recovery table of 4.6, Y0e, Y2 | the trigger is every acquisition of the writer lock, with the cheap check (ends in LF and size equals the last valid end); the two-process test (A appends and stays alive, B killed mid-line, A appends again: a repair record, no `lineage_corrupt`) is in 4.1, Y0e and the Y2 fault matrix |
| N1 untimed overlay locks | fixed | 3.5, 6 | listed as out of scope (`OverlayCommands.java:228, 238, 251, 319, 352, 404`); the claim now says the three request-bound timed waits are what E3b converts |
| N2 V2 "can only gain" | fixed | 3.5, 5.1 V2, E3a | both directions declared (no `wait`: success where it failed; explicit numeric `wait` spent in the gate: failure where it could succeed); tests `import_wait`, `import_wait_explicit` |
| N3 G6 cites | fixed | 5.1 G6 | cites 3.4; `describe(boolean)` is added by E1, it does not exist today (`Scheduler.java:285`) |
| N4 `O` label collision | fixed | 10, 4.7, 5 | owner decisions renamed **OD1 to OD7**; the commit-fault oracles keep **O1 to O6** (so "O2/O5" in the Revision 2 rows means the oracles) |
| N5 3.1 list incomplete; "fourteen" | fixed | 3.1, 3.3, 5.1, D2 | the table is one row per conditional, **C1 to C13: the count is thirteen** (the reviewer's 13 reproduced; "fourteen" was wrong), now including `bad_request` `details.field`/`allowed[]`, `cancelled` `details.phase`, `lock_queue_full`, `rk_expired`; keys with no conditional of their own are named; D2's threshold (twenty) is checked against 13 |
| N6 hello golden per wave; `DbVersions` | fixed | 3.1, 3.2, 8.1, E1, E2 | `capabilities`, `limits`, `policy` compared as required subsets, `paths`/`platform`/`analysisIdentity` masked, `platform.testHooks` asserted only by E5's tests; `Advertised` declares limit and policy names too; `DbVersions.java` has an E1 (W1) and an E2 (W2) cell |
| N7 revert leaves a stale `before` | fixed | 4.2, Y1 | `revert` refused with `has_dependents`; `cascade:true` reverts the chain; a batch always goes whole; recomputing the chain rejected |
| N8 `commit_revert` after archival | fixed | 4.2, 4.6, Y2 | rehydrated from the sealed archive in the same atomic store write, or `store_full` / `archive_unreadable`; test `revert_chain` |
| N9 subset commit and semantic dependencies | **fixed in part** | 4.2, 6, Y2 | the invariant is stated as per coarse subject, a `batch` is selected whole, and `subset_missing_type` must show fail-closed (ABORTED); whether closure needs type references is **decided by that test's result, owner Y2**, not guessed here |
| N10 undeclared dependencies | fixed | 8, every package's "Depends on", wave plan | Y2 (Y0b, Y0d, Y0e), E3b (E2), Y4a (Y2, Y1, Y3), Y4b (Y2), Y4e (Y2), E4 (E2) and P1a before E1 and every later `cc_*` file; the V6 test moved to `cc_e1`; R1 after E6 and E1 after P1a are declared in-wave sequences ("then" in the wave plan; the proof prints them) |
| N11 `rk` on `apply_overlay` | fixed | D15, 3.4 | dropped: overlays have no journal; `rk` is on `edit`, `rename`, `comment` |
| N12 26 ms figure | fixed | 3.6 | two README rows: 26 ms / +3 MB on 174 functions (`README.md:410`), 116 ms / +54 MB on 243,855 (`README.md:409`) |
| N13 work-conserving cap | fixed | 3.5, E3a | the cap holds a key back only while another key waits that is itself under its cap; test `per_key_cap_conserving` |
| N14 "This file is the design" | fixed | 8, R1 | it names `PROTOCOL-3.md`; R1's text has a `Files:` label and says every package appends to `certification.manifest` |
| N15 `Client.protocol` | fixed | 3.1, Appendix A, E1 | the first `hello` fixes the protocol (it is handled synchronously in `Connection.authenticate`); a repeat `hello` is answered with the connection's own protocol; a non-integer `protocol` is treated as absent |
| N16 `Y4c`; E0 "six tests" | fixed | wave plan, E0 | no Y4c exists, said; E0's wording follows the E0 convention (a premise that does not hold is dropped); on hydra.3 all six were CONFIRMED (`_logs/E0/baseline1.log`, `baseline2.log`) |
| N17 citation hygiene | **accepted, no renumbering** | header | README citations stay at the design-branch tip (the header already says so); revision 3 adds that the cited phrase is quoted where it helps and that the other evidence is cited by path |
| W `cli.py` unowned | fixed | 7.1, 8.1, 8.2, Y0e | Y0e, W1 |
| W `api.py` stubs need owners | fixed | 8, 8.1, 8.2, D34, Y2, Y4b, Y4e | one handler registry built by Y2 (W2); no other package edits `api.py` |
| W `has_overlays`/`expected_state` bypass the `.bak` | fixed | 8.2, 8.1, Y1 | Y1 (W1), `durable.exists`; test |
| W record-bearing writers outside `durable`; "~52 sites" | fixed | D14, 8.2, 4.1 item 4 | counted from the AST gate at `589432e`: 41 sites outside `durable.py` (11 non-record, 8 record-bearing in 4 writers, 22 artifacts); owner table in 8.2 (Y1, Y0e) |
| W Y0a edited unowned test files | fixed | 8, 8.1 | `tests/test_address_maps.py` and `tests/test_query.py` are Y0a's explicitly, with the rule that a format change owns the tests that hand-write it |
| W `MAX_OUTSTANDING` | decided | 7.6, Y0c, 8.2 | per lane (8 and 8, total up to 16) |
| W where `catalog` is reported | decided | 7.7, Y0d, 8.2 | `backend action=status` and `backend help` only; the hash covers the tool table only |
| W `AppendLog` 32 MiB budget | fixed | 4.1 item 3, 6, 8.2, Y0e | streamed reads and a tail window; owner Y0e (W1); the interim limit is recorded in section 6 |
| W v3 store read with `require_seal=True` | fixed | 8.2, Y1 | Y1 (W1) |
| W lone surrogate in a seal | decided | 3.4 | tolerated in seals and bundles (Python-only), refused in manifests |
| W `EngineError` cap on `next`; `unittest.main()` guard; `write_daemon_config`, `runtime` writers | fixed | 7.6, 8.1, 8.2, Y0e | Y0e (W1); `config.json` goes through `atomic_write` without a seal (the engine's launcher reads it) |
| W Y0b retry decisions (`close_project` and others, lost-reply behaviour) | recorded | 4.3 | recorded as decided; no behaviour change |
| W E0 review (`import_wait` signature, `--require-v3`, 8.1 rows) | fixed | E0, 9.3, 8.1 | `max(importsMs) >= 19000`; gate 9.3 always passes `--require-v3`; `dt_baseline.py` and `characterization/v3/` are in the matrix |
| W Y0a write cost | recorded | 9.10 | about 16 ms per record on D:, added to the gate-9.10 measurements |

Also while re-reading the whole file: the Contents, D1 to D34, G1 to G8, V1 to V7, C1 to C13, the packages (now
including Y0e), the waves and 8.1 were cross-checked (counts: 34 decisions, 13 reply-shape conditionals, 6
behaviour gates, 8 G rows, 7 V rows); the `OD` labels and the oracles no longer collide; the 8.1 matrix, the
wave plan and the packages' `Files` lists agree (the proof script's remaining differences are test files, which
are owned by name).

**Revision 2 (answers the independent review).** Docs only; no code. Every claim changed here was checked
against the code named in the text before the text was changed. Nothing in the review was rejected; where
the fix differs from the reviewer's first suggestion the table says so.

| Item | Disposition | Where | Note |
|---|---|---|---|
| B1 AppendLog torn tail | fixed | 4.1 item 3, 4.4, 4.6 (recovery table, `publish_torn`), D10 | writer-side repair under the lock (preserve fragment, truncate, record), readers ignore a torn tail, `publish_torn` then a successful new commit, per-offset cut test |
| B2 commit watermark | fixed | 4.2, 4.6 steps 1, 5, 7, 9, 4.7, 4.9, D32, O2/O5, Y1/Y2 tests, App. B8 | scalar `committed_through` replaced by a committed-id set (`commits[].ids`); exact subset and skip semantics (record is the unit, dependency closure, skip propagation, drift pre-pass); the marker carries `base` and `committed_sha256` |
| B3 compatibility claims | fixed | 3.1, 5.1, 5.2, D2, D16, D18, 1, matrix | one table of every v2-visible change: eight gated on v3 (G1-G8: `expect`, lane move, fair key and cap, validate-before-wait, progress `queue`, `describe` `tryLock`, new request fields, gate refusal code), seven declared visible (V1-V7) with a reason and a v2 behaviour test (`cc_*.py`, stock 1.0.0 client). The gate's v2 refusal reuses the existing `conflict` code. Counts corrected: nine reply-shape rows, fourteen conditionals, six behaviour gates; fallback threshold stated for the reply-shape count (twenty) |
| B4 ownership | fixed | 8, 8.1, wave plan, E0-E6, R1, Y*, D17, D31, 3.2, 3.7 | seams first: E1 makes the two signature changes and call sites (`Session.java:248`, `ImportCommands.java:112`), the `project` hook and four registries (`Advertised`, `Settings`, `Preflight`, `DbVersions`); `currentDbVersion()` moves to `DbVersions` (E1); E2 and E3a share no file; `laneNote` is decided by E3a and copied by E4; `Preflight` validators register per package; `bump_hydra.py` is R1's; E2 names no lane (combined check in E6) instead of a stub; matrix per file and wave plus `check_ownership.py` |
| B5 lock-wait fairness | fixed | 3.5, E3b, E0 | slices rejected (AQS re-enqueues at the tail on every timeout; untimed `tryLock` barges); one timed `tryLock` and cancel by interrupting the registered thread, with the state machine that keeps the interrupt inside the wait; tests `writer_vs_steady_readers` (also run against a polling build, must fail), `cancel_while_waiting`, `deadline_in_lock_wait` |
| N1 Journal citations | fixed | 3.4, App. A | `fieldOf` `Journal.java:117-125`, `lastAt` `:103-114`, file is 127 lines |
| N2 README line shift | fixed | header convention, D2, 3.4, 4.6, App. A | 986-990 to 988-992, 1001-1002 to 1003-1004, 1009-1012 to 1011-1014; also `:971` to `:973`, which the review did not name; convention: Java and Python at the named commits, README at the design branch tip |
| N3 `retryAfterMs` | fixed | 3.1, 3.3 | one location, `error.retryAfterMs`, never in `details` |
| N4 failed backup verify | fixed | 3.4 | one rule: the engine removes its copy as it already does for a changed source, writes no manifest, answers `failed` with `details.verify`; the Hydralysis writer never writes the manifest |
| N5 CRC | fixed | 4.1 | CRC-32, `zlib.crc32` (Hydralysis depends on `pefile` and `capstone` only); every `CRC32C` mention removed |
| N6 `selfSha256` | fixed | 3.4 | pinned canonical form for both writers; verified that Gson (even with `disableHtmlEscaping`) escapes U+2028/U+2029 and does not sort keys, so the engine uses a small canonical serializer; test with non-ASCII paths from both writers and a fixed vector |
| N7 backup fork `writable` | fixed | 4.5 | `writable:false` on hydra.2/3 (`ForkCommands.java:82` defaults to true) |
| N8 deadlines on hydra.2/3 | fixed | 3.8, 7.2, 7.5, 7.6, P1b, Y4a | P1b is hydra.4-only; a client-side watchdog (timer, `cancel`, then close a dedicated connection) needs only 1.0.0's `send`/`wait`/`close` |
| N9 capability registry | fixed | 3.1, D31, E1 | `Advertised`; per-wave golden growth handled by subset comparison and a full golden at R1 |
| N10 overlaps | fixed | 8, 8.1 | `laneNote`, E2/E3a, `preflight`, `bump_hydra.py` each resolved (see B4) |
| N11 D12 | fixed | D12, 4.6 step 4, E2 | decided from the sidecar alone (`kind` and not `disposable:false`); Hydralysis rewrites the sidecar of a generation it makes on hydra.2/3 before the manifest hash |
| N12 compaction | fixed | 4.2, 6 | committed records archived (never deleted) at the next `FINALIZED`; the latest commit's records stay for revert; the pending cap is listed as a limit |
| N13 stale `overlay_state` | fixed | 4.6 step 5, 4.7, Y1, Y2 | commit clears the option in the candidate (`state:null`), the marker's `base` and `committed_sha256` make a leftover mismatch, a fork of a generation clears a non-empty one |
| N14 step 7 reference | fixed | 4.6 steps 1, 7 | reference texts captured at `upTo` under `.sync.lock`; functions touched by outside records are `excluded` |
| N15 `rk` replay | fixed | 3.4 | the journal stores the per-op result, not the reply; the replay reply is reconstructed and said to be so |
| N16 quick hint | fixed | 3.4, 6 | trust-based; a non-cooperative quick script keeps its slot past its timeout |
| N17 D4 visible | fixed | 5.2, R1, section 10 | required release-notes line |
| N18 cumulative backups | fixed | 4.5 | confirmation text and doctor state the cumulative size; `backup_root_warn_gb` |
| N19 fixture count | fixed | 9.1 | 8 programs, 4 x86 and 4 x64, from `_golden/sets/fixtures.json`; the set totals 4,497 functions against 3,959 in `docs/golden-harness.md:143` (not reconciled, not relied on) |

Also corrected while re-reading: two stale cross references (`private` is 3.6, the backup schema is under
3.4), the claim that each package edits a "status table" of this file (there is none), and the
`Session.java` ownership sentence of the first revision (D17, 8).

**Revision 1.** The first version of this file (one commit on `design/protocol-3`).
