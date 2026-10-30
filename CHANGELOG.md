# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

A version is the Ghidra version a release is built on, then `-hydra.` and a counter (for
example `12.3-hydra.1`); its tag is `v` and the version. Releases are on
[GitHub](https://github.com/RusticStack/hydra-engine/releases).

## Unreleased

Not yet released; a release renames this heading to its version and names the upstream commit
it is based on.

### Documentation

Wording corrected to what is true today; no behaviour changed. The claim ids are those of the
claims audit in `Ghidra/Features/HeadlessSession/PROTOCOL-3.md`, section 8.3.

- Concurrency (C1, C3, C4, U1, U2, U3): writes are serialized and no corruption was seen in the
  tests listed; collisions are only detected when you pass `expect`. Native commands stay in the
  quick lane while imports and analyses run in the long lane; scripts share the long lane, and
  the readers of a program being analysed wait for its lock. Each program and project has its
  own lock, but they share the daemon's lane slots and import gate. Waiting requests are
  admitted round-robin by connection, and while another connection waits a per-connection cap limits how many slots one connection runs. The
  documents say "several clients (tested with up to 4 clients)" where they gave no limit.
- Scripts, cancel and dead clients (C2, C5, C7): a contained script's changes are rolled back and
  never saved, but other clients can see them while it runs. `cancel` stops requests waiting for
  a slot or for a program lock, and cooperative scripts. A disconnected client's requests are cancelled and its uncommitted changes rolled
  back when its running request ends.
- Imports (C6): an import waits in the import queue; at the front it still needs a long slot. With
  a numeric `wait` it fails `busy` when that `wait` runs out; without a numeric `wait` it waits
  for the slot without limit (V2).
- Facts (C8, C11, U10, U11): one daemon per state directory and instance; small fixes to
  Ghidra classes (three at the time of 12.3-hydra.3; see Unreleased below for the storage change); a native decompile takes about 1 to 45 ms by function size (7 ms in
  the benchmark function); the 7.0-7.8 s of `analyzeHeadless` was measured on stock Ghidra 12.1.4.
- Headless only (U8, U14): there is no GUI, and projects Hydra Engine writes cannot be opened by
  Ghidra 12.2 or 12.1.4. Scripts that use the headless API run unchanged; GUI-only extensions do
  not apply. "Other processes can read it" replaces the sentences that named an interactive
  Ghidra tool as a reader of a read-only project.
- Read-only checks (U12): the tests compare file sizes and modification times (and contents up to
  1 MiB in the upgrade cache test), not a byte-for-byte copy of every file.
- `how-it-works.gif` is labelled as an illustration (U5).

### Protocol 3 and the lock changes (not released)

Text prepared for the 12.3-hydra.4 section; the release renames the heading. It lists what the
code does on the integration branch at the time of writing. It makes no guarantee: a statement
that a failure "cannot" happen appears only with the test that was run for it, and the
guarantees that hydra.4 may make are listed with their tests in
`docs/release-notes-12.3-hydra.4.md`.

- **Protocols.** One port serves protocol 2 and protocol 3. The endpoint file and the `ready`
  event carry `protocolMin` (2) and `protocolMax` (3); `protocol` stays 2 for a client that
  asks for nothing newer. `minClient` stays `1.0.0`, so no existing client is rejected by this
  engine. `ghidra_session.py` 1.1.0 asks for protocol 3 and falls back to 2. Hydralysis 0.4.x
  refuses a hydra.4 engine by its own pin; clients of hydra.2 and hydra.3 keep working at
  protocol 2.
- **Changes a protocol 2 client can see.** Everything else a protocol 2 client does is
  unchanged and checked against the vendored 1.0.0 client (`examples/stock/`,
  `examples/client_compat_tests.py`); these are the declared exceptions, by name:
  - V1, the upgrade gate: `open_program` with `writable` and `upgrade` on a canonical project in
    an older format is refused with `conflict` (`details.reason` `backup_required`) unless the
    request carries a valid `backup`; a fork is allowed.
  - V2, the import wait: an import without `wait` no longer fails `busy` ten seconds after it
    reaches the front; an import with a numeric `wait` spends one budget across the gate, the
    slot and the project lock, not one per stage.
  - V3, bounded release of a dead client: its slots and its locks are released after
    `cleanupGraceS` and `abandonWaitS` (15 s and 5 s by default) instead of waiting for the
    request to end; the 600 s waits of `disconnect` and `leaveProject` for owners and writers use
    the same bounds.
  - V4: a request for a program held by an abandoned request answers `busy` at once.
  - V5: `cancel`, and a `timeout` deadline, end a request that waits in a request-bound lock wait
    (a program, a project, or an overlay's request lock site). The overlay lifecycle waits (open,
    rebuild, drop and promote of an overlay) are untimed and are not ended by `cancel`, a
    `timeout` or the release of a dead client (module README, Limits, L2).
  - V6: `protocolMin` and `protocolMax` in the endpoint file and the `ready` event.
  - V7: the sidecar of every `fork_project` gains `purpose` and `disposable`.
  - V8: a project that this engine sealed (the registry record, `SEALED.json`, or a `generation`
    or `backup` sidecar with `state` `complete`) refuses every writable path with `conflict`
    (`details.reason` `sealed`). A project with none of these behaves as before.
  - V9: a per-connection cap on running requests applies while another connection waits; the
    long lane defaults to `max(8, CPUs)` slots.
  - V10: a client that is neither owner, writer nor overlay holder leaves a program without
    taking its exclusive lock.
  - V11: concurrent `fork_project` calls to one destination give one success and `conflict`
    (`details.reason` `fork_in_progress` or `exists`) to the others.
- **Protocol 3 additions** (only for a client that asks for protocol 3): the `expect` check on
  `signature` and `data_type`, the `rk` idempotency key, `error.next`, the identity block of
  `hello` (`paths`, `platform`, `analysisIdentity`), the capability, limit and policy blocks, the
  maintenance lane for `save`, `fork_project`, `refresh`, `reopen` and `promote_overlay`, the
  `queue` key of slot waits, per-request validation before a wait, `seal_project`, backups with
  a manifest, the `isolation` and `lane` fields of `script`, and the daemon settings passed as
  `-set key=value` (the `engine` object of `config.json`).
- **Not in this text:** the `health` command and the watchdog, the resource governor and the
  killable script worker are separate packages. Until they are part of the release they are not
  described here, and nothing in this section says they exist.
- **Build identity.** The build tool does not stamp the release into `hydra.properties`; the
  release workflow does. A local build says `<Ghidra version>-hydra.dev`, which Hydralysis treats
  as a stock Ghidra. Stamp it as the workflow does (module README, "Stamping a local build"),
  and check the stamp with `tools/bump_hydra.py` of Hydralysis, which refuses an engine zip
  that carries none.
- **Headless only.** There is no GUI. Hydra Engine is headless only; projects it writes cannot
  be opened by Ghidra 12.2 or 12.1.4.
- **Limits.** Every limit of `PROTOCOL-3.md` 6.2 is stated in the module README, "Limits of
  12.3-hydra.4 and protocol 3" (L1 to L19 and R6.1 to R6.11). In short: a script that ignores
  cancel is bounded and quarantined, not stopped, until the script worker's release gate (9.14)
  passes; the overlay lifecycle waits are not cancel-aware; the leave of an owner or writer of an
  open program still queues the exclusive lock (bounded); `lane:"quick"` is a trusted hint;
  Windows x64 and JDK 25 only, no Linux or macOS claim; no power-cut test; nothing about ReFS is
  tested for this release (no ReFS volume on the release machine, owner decision 2026-10-30;
  NTFS is the release file system); the upgrade gate and the backup check guard against
  accidents and are not a security boundary.
- **NOTICE-HYDRA.** The list of modified Ghidra files was checked against the upstream commit
  `1b9e58a915cf867e106495eaa2a4b18eb4971c9d` of hydra.3: five modified core Java files, one added
  class (`VersionFileCheck`), and the build files already listed.

### Storage integrity (not released)

- Ghidra core: the header of a new version file is written and synced before the file is renamed
  to its final name (`LocalManagedBufferFile`), and the newest version is checked when a database
  is opened (`VersionedDatabase`, `LocalDatabaseItem`, the added class `VersionFileCheck`). A kill
  during a save used to leave an unopenable newest version in about 3% of kills in the crash tests
  (12 of 363); a kill batch with the change found 0 unopenable versions in 200 kills on NTFS. No
  ReFS result is stated: ReFS is not tested for this release (owner decision 2026-10-30). Release gate 9.15 (the counted kill
  batches) has not passed. The repair of a bad newest version applies only to writable forks inside declared
  disposable roots and is not wired into the daemon yet. A bounded result, not a guarantee.
- Fork publish is atomic and retryable (capability `forkAtomic`): the fork is built in a staging
  folder and published with `.gpr` last, a sidecar records its state, and a sweeper removes the
  leftovers of a publisher that died. 330 kills on NTFS left no state that a retry could not
  finish (no ReFS result is stated; release gate 9.15 has not passed) (a killed publish can leave a `.rep` without its `.gpr`, which the next call
  sweeps). A concurrent publisher of the same name now gets `conflict`.
- Protocol 3 groundwork (client 1.1.0, version negotiation, the identity block; protocol 2 replies
  are unchanged and checked against the vendored 1.0.0 client), the corruption oracle and the
  regression suites (`examples/oracle.py`, `examples/conc/`), and the design in `PROTOCOL-3.md`
  revision 8.1. None of it changes the replies of protocol 2.

### Internal

- `Session.java` (3,625 lines) is split into the state and dispatch (`Session`, 473 lines) and
  command classes by area: `ProjectCommands`, `ForkCommands`, `ProgramCommands`, `QueryCommands`,
  `EditCommands`, `Operations`, `OverlayCommands`, `ImportCommands`, `ScriptCommands`, with
  `Access`, `Requests` and `Addresses` as shared helpers. No behaviour or protocol change: every
  reply is identical, field order included. The layout and how to add a command are in
  `Ghidra/Features/HeadlessSession/ARCHITECTURE.md`.
- New `examples/characterization_tests.py` and `examples/characterization/`: the exact replies
  of every session command, recorded before the split and compared after it. It needs no binary
  and no game data; it is the safety net for the protocol changes planned next.

## 12.3-hydra.3

Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-27,
commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, merged into the Hydra Engine branch with a
plain merge commit (no rebase): 0 conflicts. The previous base was `057a646233`; the merge brings in
35 upstream commits (17 that are not merges) and touches 29 files, none of which Hydra Engine
changed. `git merge-tree` predicted the merged tree `069259b499` and the merge produced the same
tree.

### Upstream changes picked up

- Decompiler (C++, so the native `decompile.exe` is rebuilt): GP-7212 (`RuleRangeMeld` extra
  pull back for offcut matches, `ruleaction.cc`), GP-7414 (`truncatePointer` checks for a
  constant varnode), GP-7423 (`findCbranch` in `checkCommonCbranch`, `coreaction.cc`,
  `jumptable.cc`).
- GP-1 `ghidra.util.datastruct.Range` is `long` based instead of `int` based.
- GP-7418 Ghidra URL encode and decode fixes (`GhidraURL`); GP-7416 loader options built with
  constructors deprecated in 12.2 no longer lose headless `-loader-*` arguments (`Option`).
- Bounds-checking fix in `StaticValueByteProvider`, symbol path parsing (`SymbolPathParser`),
  Objective-C message analyzer, Windows RTTI script, and dialog and marker fixes in code the
  headless install does not contain.

### Database format gate

Nothing in the database or language layers changed: the merge touches no file in
`Ghidra/Framework/DB`, `Ghidra/Framework/SoftwareModeling`'s `program/database` packages or any
processor (`Ghidra/Processors`); `ProgramDB.DB_VERSION` is still 33,
`DataTypeManagerDB.DB_VERSION` 3, `DataTypeArchiveDB.DB_VERSION` 5, `ProgramUserDataDB.DB_VERSION`
1, `SlaFormat.FORMAT_VERSION` 4, `LocalBufferFile.HEADER_FORMAT_VERSION` 1. Projects of
12.3-hydra.2 open unchanged. `LocalBufferFile` still has both GP-7261's size checks and Hydra's
truncate-before-close for temporary buffer files (`3229f6e79f`).

### Decompiler gate

The decompiler output of this build was compared with 12.3-hydra.2 (`golden.py`, one program
function at a time, C text hashed):

- KotOR (an x86 game executable, 8616 functions): 8616/8616 identical to 12.3-hydra.2 on all three
  decompile paths (explicit, explicit-program and production), and identical between two runs of
  12.3-hydra.3.
- x86 fixtures: identical. x64 fixtures: exactly one function per program differs, the same CRT
  `strncmp` (125 bytes) in all four; the change is GP-7212's. The 100% fixtures profile therefore
  fails by one function per x64 program until those baselines are re-recorded.
- GP-7423 and GP-7414 changed no output in this corpus (no regression seen; not a verified
  improvement). KotOR is x86 only.
- Timing: no regression above the run-to-run noise of a machine shared with other Java processes
  (interleaved A/B medians: 3.40 ms for 12.3-hydra.2 against 3.37 ms for 12.3-hydra.3); one raw pair
  of back-to-back runs showed +14 to +16%, which the interleaved runs did not reproduce.
- A project saved by 12.3-hydra.3 opens in 12.3-hydra.2 and back. This is expected: both builds
  use the same database format, so it is not independent evidence about the format.

### Build and tests

`gradle buildHeadless` (JDK 25, Gradle 9.8.2, Visual Studio Build Tools) built the headless install
for Windows x64, native decompiler included: `decompile.exe` and `sleigh.exe` were compiled from the
merged sources, not copied. On that install (NTFS volume): `session_smoke.py` passed (34 checks),
`contract_tests.py` 5/5, `daemon_tests.py` 31/31 (including `import_queue`, `import_isolation`,
`parallel_imports`, `import_speed`, `upgrade_cache` and `fork`); `legacy_overlay` and the
older-format half of `upgrade_cache` need a project saved by Ghidra 12.1.4 and were skipped. Not
exercised: the ReFS-only behaviour (block-clone fork, slow close of a temporary buffer file). A
stock `analyzeHeadless` import with `-loader-*` arguments applied them; upstream's tests for
`GhidraURL`, the protocol connector and `SymbolPathParser` pass (55 tests).

### Documentation and licensing (no change in behaviour)

- **README**: Hydra Engine is described as a fork of Ghidra 12.3 DEV that depends on it (the
  project format, decompiler, analyzers and scripts are Ghidra's), not as an independent project.
- **Speed**: the warm decompile time is qualified as size-dependent. The 6.7-7.1 ms of the benchmark function
  is one function whose size was not recorded; measured by the owner on a KotOR
  executable on 2026-10-27, a warm decompile took 0.7-2.1 ms for a one-byte function and 35-45 ms
  for a 6.7 KB function of 29 basic blocks.
- **Writes**: they are serialized, and no corruption was seen in the tests listed in the module
  README; they are not collision-checked by default: shared writes are last-writer-wins per value, and `expect` is opt-in per call. The
  wording "write without stepping on each other" is replaced accordingly (README and module
  README).
- **Platform and limits** section: releases are Windows x64 only, JDK 25 is required, one daemon
  per state directory, `fork_project` is a block clone only on ReFS (a full copy elsewhere),
  changes are kept only by `save`, and the project upgrade from 12.1.4 is one-way.
- **Hydralysis** (renamed from RusticRE): a status note says its repository, command and
  `HYDRALYSIS_ROOT` are not published yet; the links stay.
- **NOTICE-HYDRA** rewritten as the Apache-2.0 section 4(b) notice of modifications: it lists
  every modified upstream file with what changed, and each of the three modified Java files
  (`LocalBufferFile`, `LocalDatabaseItem`, `SleighLanguageFile`) has a one-line comment saying so
  (no code change).
- **Release archives** now ship `NOTICE` and `NOTICE-HYDRA` next to `LICENSE`: in the headless
  install's root (`gradle/hydra/headless.gradle`) and in the client zip
  (`.github/scripts/package-client.sh`); the release workflow checks the unzipped engine for all
  three.
- **CONTRIBUTING**: the upstream sync policy (merge never rebase, one `sync/upstream-YYYY-MM-DD`
  branch cut from `origin/main`, the golden decompile diff gate, the upstream commit recorded in
  the changelog, the database format constants check, `legacy-12.1.4` frozen and end of life) and
  a complete list of the upstream files that can conflict.

## 12.3-hydra.2

Released 2026-10-26. Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-26,
commit `057a646233edfb21768a42a0aabc1d1a7709da19`: the same upstream commit as 12.3-hydra.1
(upstream had no newer commit when this release was cut).

### What's new for integrators

Several agents can now change things at the same time, each in the way that fits its work:

- **A working copy of a project** (`fork_project`) while every other client keeps reading the
  master: a block clone on ReFS (about 0.2 s and 3-5 MB for a 1.5 GB project), a full copy
  elsewhere (8.5 s for the same project to NTFS), with the source
  and base revision recorded next to the fork.
- **A private overlay** of a program others read (`open_program` with `overlay`,
  `apply_overlay`): renames, labels, comments, signatures and data types only that client sees,
  never saved unless promoted into a working copy (`promote_overlay`).
- **Several writers**: several clients write one project (different programs in parallel), or
  one program in shared mode (`"share": true`), with every change journalled with its author,
  `expect` to detect lost updates, an atomic `edit` command and `discard_edits`.
- **Revisions and `refresh`**: answers say when another process saved a project a read-only
  view serves (`stale`); `refresh` reopens it for all its clients at once.
- **Who holds it, and what to do**: `busy`, `conflict` and `not_owner` name the holder
  (`holderInfo`) and suggest the action (`retry`, `fork_project` with a ready request, an
  overlay, `share`, `reread`, `open_read_only`).
- **Imports in parallel** (`maxImports`), with a visible, cancellable queue in `status.imports`.
- **Per-request `client`/`harness` labels**, so one MCP server serving several agents can tell
  them apart in holders, `status`, the import queue and `cancel`.
- **A versioned integration contract**: `hello` and `status` carry `protocol`, `minClient`,
  `hydraVersion`, `ghidraVersion` and `installId`; the client ships as its own release asset,
  `hydra-client-12.3-hydra.2.zip`, and refuses an engine it cannot drive. The export contract
  of long scripts (artifact path, progress, cancel, partial files) is documented and tested.

### Compatibility

- **Protocol 2, unchanged.** Everything above is new commands and new fields; nothing was
  renamed or removed, except that the `busy` details of a program lock carry the program's key
  in `program` (its project path moved to `path`). The engine answers `minClient: "1.0.0"`.
- **Client 1.0.0** (`ghidra_session.py`, `CLIENT_VERSION`) is the first versioned client;
  pin it together with the engine. The unversioned client of 12.3-hydra.1 still speaks protocol
  2 but does not check the engine.
- **Projects**: a project saved by this build cannot be opened by Ghidra 12.2 or 12.1.4
  (upstream `master` writes data type databases at version 3). Projects analysed with 12.1.4
  open read-only without being written, upgraded in memory and then served from the upgrade
  cache; `fork_project` makes a writable copy that leaves the original as it was. The
  `legacy-12.1.4` branch remains for projects that must stay on 12.1.4.
- **Platforms**: built and tested on Windows 11 x64 only (locally and in the release
  workflow). Linux and macOS are not released or tested routinely.

### Downloads

- `hydra-engine-12.3-hydra.2-win_x86_64.zip`: the headless install for Windows x64 (`gradle
  zipHeadless`); the release workflow ran the three test suites on it after unzipping it.
- `hydra-client-12.3-hydra.2.zip`: `ghidra_session.py` (standard library only) stamped with
  this release, `LICENSE` and a short `README.txt`.
- `SHA256SUMS` for both.

You need a JDK 25 and Python 3.10 or later; the install has no JDK.

### Known limits

- The data type database version 3 limit above, and a development snapshot as the base
  (upstream `master` is Ghidra's next version under work, not a Ghidra release).
- Overlays change only through their five operations (rename, label, comment, signature, data
  type) and show the program as stored when they opened, not other writers' unsaved changes.
- A fork is a block clone only on ReFS (Windows 11 24H2 and later); on NTFS it is a full copy,
  which `auto` mode refuses above `forkCopyLimitMb` (default 2048).
- The author journal lives in the daemon's memory while the program is open and keeps the last
  200,000 entries; `discard_edits` reverts renames, labels and comments only.
- There is no GUI: headless only, with no help, javadoc or Python type stubs.

### Added

- **Holder information in `busy`, `conflict` and `not_owner`** (HeadlessSession). The error
  details name who holds the project, program or lock: `holderInfo` (`client`, `name`,
  `harness`, `label`, `command`, `heldMs`; for another process, the user, host and time from
  Ghidra's project lock file and whether that process is alive), the project or program identity
  (`project`, `gpr`, `program` key, `path`, `sha256`), and `suggest`: `retry`,
  `fork_project` (with a ready `suggestion` request) where a working copy is the answer,
  `share` (join a shared program), `reread` (a value changed since it was read), or
  `open_read_only`. `holder` stays a string as before; everything else is new fields.

- **`fork_project`** (HeadlessSession): copies a project into a working copy for the caller
  while the source and its read-only views stay open and in use. A block clone on ReFS (Windows
  11 24H2 and later), else a full copy; `mode` `auto` (clone, or a full copy up to
  `forkCopyLimitMb`, default 2048), `copy-on-write` (clone or refuse) or `full`. The answer has
  the new project id, the paths, the source's identity and base revision, `method`, `cloned`
  (measured), `bytes`, `files` and times. The fork records its source, base revision and lineage
  in `<name>.fork.json` next to its `.gpr`, shown as `fork` by `project`. A source another
  client or process writes is refused, naming it. New launcher setting `forkCopyLimitMb`
  (`GHIDRA_SESSION_FORK_COPY_LIMIT_MB`), daemon option `-forkCopyLimitMb`.

- **Revisions and `refresh`** (HeadlessSession): every project and program has a `revision`
  (a fingerprint of the saved files), shown by `open_project`, `project`, `projects`,
  `open_program`, `info`, `save` and `status` with `diskRevision`, `stale` and `generation`.
  Answers carry `stale` (a read-only view whose project another process saved) and, once,
  `refreshed` (another client refreshed it). New command `refresh` (alias `reopen`) reopens a
  read-only view for all its clients at once, under the same keys. The Python client gains
  `call_raw` and `last_response`.
- **Integration contract** (`Ghidra/Features/HeadlessSession`, `support/ghidra_session.py`):
  `hello`, `status` and the endpoint file now carry `protocol`, `minClient`, `hydraVersion`,
  `ghidraVersion`, `installId` and `startedAt`; the Python client has a `CLIENT_VERSION`
  (`1.0.0`) and refuses, with `IncompatibleError` (exit code 4 on the command line), an engine of
  another protocol or one whose `minClient` is newer than itself; `status` and `stop` still work
  on such an engine. `ghidra_session.py version` prints the client's version. README: "Pinning
  and upgrading", and a compatibility statement for projects analysed with Ghidra 12.1.4.
- **Client release artifact**: the release workflow also publishes `hydra-client-<version>.zip`
  (the standard-library-only `ghidra_session.py` stamped with the release, `LICENSE`, a short
  `README.txt`), listed in `SHA256SUMS`. `.github/scripts/package-client.sh` builds it and
  checks the packaged file; CI runs it as a dry run.
- **Status shows requests**: each client in `status` lists its unanswered requests (`id`, `cmd`,
  `artifact`, `ms`, `message`, `progress`, `maximum`) and its `clientVersion`.
- **Script exports**: `script` takes an optional `artifact` (a path the script writes), echoed in
  `status` and in the result; `examples/scripts/ExportJsonl.java` is a sample export with
  progress and an inspectable partial file; README "Scripts" states the export contract
  (output outside the project, not capped by `maxChars`, partial files after cancel and shutdown).
- **Concurrency documentation**: README "Who can do what at the same time": readers, writers,
  projects, imports, and what `conflict`, `busy` and `not_owner` mean.
- **Tests**: `examples/contract_tests.py` (identity fields, client compatibility, a 600,000-line
  export with progress, cancel and shutdown), run by CI and the release workflow.
- **The import queue is visible and cancellable.** Imports that cannot run yet (one at a time
  when this was added; up to `maxImports` since "Imports run in parallel" below) queue
  first-come, first-served without holding a scheduler slot. `status.imports` shows the
  holder (client label, project, file, running time), the queue with each entry's position and an
  estimated wait (from the durations of earlier imports), and the history. A queued `import`
  sends `progress` events "waiting behind ..." and its answer reports `queue` (`waitedMs`,
  `positionAtEntry`, `behind`). Cancelling a queued import removes it without touching the
  running one; cancelling the running one starts the next. A numeric `wait` now limits the queue
  wait; without one a queued import waits in the queue without limit, and at the front it still
  needs a long slot and fails `busy` after `wait` (10 s default).
- **Per-request `client` and `harness` labels.** Any request may carry them; they replace the
  connection's name for that request in `busy`/`conflict` holders (`holder` and `holderInfo`), `status` (requests, scheduler
  lanes, owner of a writable program, `youAre`), the import queue and the log, and they scope
  `cancel` (`all` reaches only that label's requests; `target` refuses another label's request).
  Ownership is unchanged (still per connection). One MCP server serving several agents can now
  tell which agent holds a program or an import. `ghidra_session.py`: labels on any `call`, and
  `labelled(client=, harness=)` views with `cancel_all()`.
- `daemon_tests.py`: `import_queue`, `import_isolation`, `caller_labels`; `--raw-mb`.

- **Shared writing** (HeadlessSession): `open_program` with `"writable": true, "share": true`
  lets several clients write one program at once. Each change is its own transaction,
  committed one at a time under the program's exclusive lock and visible to all; last writer
  wins, and `expect` on renames, labels and comments (also as `edit` operations) turns a lost update into
  `conflict` (`reason: "changed"`) naming the last editor. Every change to a writable program
  is journalled with its author (`journal`; `journalSeq`, `unsavedEdits`, `savedSeq`); new
  commands `edit` (operations, all or none) and `discard_edits` (revert one author's unsaved
  renames, labels, comments). A writer that dies loses only its uncommitted change; when it was
  the last writer, the unsaved work is kept (program and project stay open) until a client
  joins and saves or discards it. Owner and shared mode do not mix on one program. Tested with
  4 clients x 2 threads, 3,200 edits and 64 saves: none lost, journal complete, reopen clean.
- **Several writers in one project** (HeadlessSession): `open_project` writable while other
  clients use the read-only view now reopens it writable in place (same id and keys, their
  programs reopened, overlays rebuilt, `refreshed` once) instead of `conflict`; refused only
  when another process holds the project lock. A second writable open joins; writers of
  different programs of one project work in parallel (tested with concurrent renames,
  comments, analysis and saves). `not_owner` adds `alternatives: ["overlay", "fork_project"]`
  and an `overlaySuggestion`.
- **Overlays** (HeadlessSession): a client's private annotation view of a shared program.
  `open_program` with `overlay` opens one: its own program object over the stored file
  (changeable, never saved), measured at 116 ms and +54 MB heap for a 243,855-function program.
  `apply_overlay` applies `rename`, `label`, `comment`, `signature` and `data_type` operations
  atomically and logs them; `info`, `functions`, `decompile`, `script` (contained), `rename` and
  `comment` take `overlay`; `drop_overlay`, `overlays`; `promote_overlay` replays the log into a
  writable copy (a project the client opened writable, or a new fork) and saves it. Each overlay
  shows `overlayVersion`, the program's SHA-256 and revisions, in its answers, `info` and
  `status.overlays`. A refresh rebuilds overlays from their logs; a client's disconnect drops
  its overlays.

### Changed

- **Imports run in parallel** (HeadlessSession). Up to `maxImports` imports (new launcher
  setting and daemon option `-maxImports`; default one per four CPUs, 1 to 4) run at once, into
  different projects or into one; more queue as before. Imports no longer set the process-wide
  active project: nothing on Ghidra's load path reads it (the README's "Parallel imports" lists
  what the load path shares and why parallel loads work): four 12-25 MB PEs imported at once took 64 s
  against 165 s one after the other, with identical programs. The gate covers the load and the
  save; `analyze: true` analyses afterwards in the import's long slot, as before. The same file sent twice at
  once into one project is imported once: the second waits and answers `existing`, with
  `sameFileImport`. `status.imports` gains `maxImports`, `running` and `history.peakRunning`
  (`holder` is the oldest running import); an import's `queue` gains `runningAtStart`. Opening an
  upgrade cache copy no longer goes through the import gate.
- `daemon_tests.py`: `parallel_imports`, `import_kill`, `import_readers`, `import_speed`
  (`--big`, `--big-analyze`); `import_queue` runs with `maxImports` 1.
- The project files the upgrade cache keys and copies leave out Ghidra's transient files in a
  `.rep` (`tmp<n>.ps` pre-save copies of programs open for update, `tmp<n>.tmp`), so that a
  project another process has open for update keeps its identity until it is saved. Cache
  entries made before this are rebuilt once.
- The `busy` details of a program lock carry `program` as the program's key
  (`p1:/path`), like every other error, instead of its project path (now in `path`).
- A `script` result's `changed` now says whether the script changed the program (always false
  for a contained script, whose changes are rolled back); the new `unsaved` says whether the
  program has unsaved changes, which is what `changed` used to report.

### Fixed

- **A writer's read-only script was journalled as a change** (HeadlessSession). A script run by
  an owner or shared writer of a program with unsaved changes (from anyone) answered
  `changed: true` and added a `script` entry to the author journal, although it changed
  nothing; on a shared program every query script did so. The session now compares the
  program's modification number before and after the script. Found by `daemon_tests.py edit`.
- **A program killed while being written into a project was listed but could not be opened**
  (Ghidra, `Framework/FileSystem` `LocalDatabaseItem.create`). Ghidra wrote the new item's
  property file, with its file type, before streaming the database in, so a process killed
  mid-write (an import's save, or a *Save As*) left an item that every later open listed as a
  program and failed to open ("Unrecognized file format"). The file type is now written once
  version 1 of the database is complete; an item killed earlier is removed by Ghidra's existing
  repair the next time its folder is listed. Found by `daemon_tests.py import_write_kill`.
- **`kill` returned before the daemon's process was gone** (`ghidra_session.py`). It waited for
  the instance lock only; a daemon killed during a large write on ReFS kept its project lock
  for seconds more (closing a file with many dirty pages waits for them), so a daemon started
  right after got `conflict` ("locked by another process", `live: true`). `kill` now also waits
  for the process to exit (within its 30 s). Found by `daemon_tests.py import_write_kill`.
- **A daemon started after a crash could take minutes to become ready** (HeadlessSession).
  Ghidra's `DBInitializer` deletes the buffer cache files dead processes left in the user temp
  folder before start-up goes on; with `tmpdir` on ReFS, deleting the large cache file of a JVM
  killed while it held a big program waits until ReFS has written its dirty pages back
  (measured: 43 s, 61 s and once 222 s, beyond the launcher's 180 s wait). On a class cache hit
  the session now does this cleanup itself on a background thread, and on Windows renames each
  file first (which fails while any live process has it open), truncates it to 0 bytes (which
  drops its unwritten pages) and deletes it: the next daemon was ready in 0.35 s. Found by
  `daemon_tests.py import_write_kill`.

### Tests

- `daemon_tests.py`: `edit` (the `edit` command, all or none, `expect` naming the author;
  `discard_edits` deleting newly created labels), `overlay_owned` (an overlay of a program
  another client owns writable, with the owner saving while it is open), `refresh_force`,
  `legacy_overlay` (overlays of a 12.1.4-format program, during and after its upgrade cache
  build), `orphan_shutdown` (orphaned shared-write work discarded and logged at shutdown),
  `import_write_kill` (the daemon killed during an import's final write: the program absent or
  complete, never half).
- `parallel_imports` cancels its import during the load: on a fast CI runner its fixed 1 s
  delay let the cancel arrive during the final write, which is not cancellable (README,
  "Parallel imports", now says so).

## 12.3-hydra.1

Released 2026-10-26. The first release. Based on upstream Ghidra `master` (12.3 DEV) as of
2026-10-26, commit `057a646233edfb21768a42a0aabc1d1a7709da19`.

### Downloads

One zip, `hydra-engine-12.3-hydra.1-win_x86_64.zip`: the headless install for Windows x64
(`gradle zipHeadless`), on which the release workflow ran both test suites after unzipping it.
You need a JDK 25 and Python 3.10 or later; the install has no JDK.

### Known limits

- **Projects saved by this build cannot be opened by Ghidra 12.2 or 12.1.4.** Upstream `master`
  writes data type databases at version 3; 12.2 and 12.1.4 read version 2. A project opened
  read-only is not written; open older projects writable only from a copy. The
  `legacy-12.1.4` branch serves projects that must stay on 12.1.4.
- **Based on a development snapshot.** Upstream `master` is Ghidra's next version under work
  (12.3 DEV), not a Ghidra release.
- **Windows only.** CI and releases build and test on Windows. The module and launcher have no
  Windows-only path, but no Linux or macOS claim is made: neither is released or tested.
- **There is no GUI.** Headless only: no help, javadoc or Python type stubs; `gradle buildGhidra`
  still builds the whole source tree, from source.

### Added

- **HeadlessSession module** (`Ghidra/Features/HeadlessSession`): a shared headless session
  daemon, one per state directory and instance. One JVM serves several projects and clients over JSON lines on an
  authenticated loopback socket (or stdio), with protocol version 2.
  - Projects opened in place: read-only without a lock, or writable with one.
  - Programs opened and switched without importing; imports with any Ghidra loader,
    deduplicated by SHA-256.
  - Analysis, decompiling, renames, comments, saves, and GhidraScripts (Java or Python) with
    arguments; scripts on programs a client does not own run contained and are rolled back.
  - Two scheduling lanes (quick and long, round-robin by connection), one writer and several
    readers per program, per-client cancel, a disconnected client's requests cancelled and its
    uncommitted changes rolled back when its running request ends, idle shutdown, warm programs
    kept open for the next client.
- **`ghidra_session.py`**: a standard-library-only Python launcher, daemon manager and client
  (`connect()`), with no `.bat` or `.sh` launcher. Fast start with a class search cache and,
  on JDK 25+, an AOT cache.
- **Tests**: `examples/session_smoke.py` and `examples/daemon_tests.py`.
- **Headless build** (`gradle buildHeadless`, `gradle/hydra/headless.gradle`): an install
  without the modules only an interactive tool uses, the help, javadoc and Python stubs, and with
  a check that no module of the install depends on one it leaves out. `gradle buildGhidra` still
  builds the whole source tree.
- **Repository**: this README (Ghidra's original is `README-GHIDRA.md`), `NOTICE-HYDRA`, a
  security policy and contributor guide in `.github/`, issue and pull request templates, and CI
  (`.github/workflows/ci.yml`) that builds the headless install and runs both test suites.
- **Releases** (`.github/workflows/release.yml`): a tag `v<version>` builds the headless zip on
  Windows, runs both test suites on the unzipped install, and publishes the zip, `SHA256SUMS`
  and this file's section as a GitHub Release.
### Branches

- `main`: the above, on upstream `master`.
- `legacy-12.1.4`: the same module on Ghidra 12.1.4, kept for projects analysed with 12.1.4.
