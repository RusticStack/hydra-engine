# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

A version is the Ghidra version a release is built on, then `-hydra.` and a counter (for
example `12.3-hydra.1`); its tag is `v` and the version. Releases are on
[GitHub](https://github.com/RusticStack/hydra-engine/releases).

## Unreleased

Not yet released; a release renames this heading to its version and names the upstream commit
it is based on.

## 12.3-hydra.2

Released 2026-10-26. Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-26, commit
`057a646233edfb21768a42a0aabc1d1a7709da19`: the same upstream commit as 12.3-hydra.1 (upstream
had no newer commit when this release was cut).

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
  `expect` against lost updates, an atomic `edit` command and `discard_edits`.
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
- Headless only: no window, help, javadoc or Python type stubs.

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
  wait; without one a queued import waits until it runs or is cancelled.
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
  what the load path shares and why it is safe): four 12-25 MB PEs imported at once took 64 s
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
  Windows-only path, and a one-off dry run of the release workflow on 2026-10-26 built Linux x64
  and macOS arm64 installs that passed both test suites, but neither is released or tested
  routinely; build from source there (`gradle buildHeadless`).
- **Headless only.** No window, help, javadoc or Python type stubs; the full Ghidra build is
  still `gradle buildGhidra`, from source.

### Added

- **HeadlessSession module** (`Ghidra/Features/HeadlessSession`): a shared, per-user headless
  session daemon. One JVM serves many projects and many clients over JSON lines on an
  authenticated loopback socket (or stdio), with protocol version 2.
  - Projects opened in place: read-only without a lock, or writable with one.
  - Programs opened and switched without importing; imports with any Ghidra loader,
    deduplicated by SHA-256.
  - Analysis, decompiling, renames, comments, saves, and GhidraScripts (Java or Python) with
    arguments; scripts on programs a client does not own run contained and are rolled back.
  - Fair scheduling (quick and long lanes, round-robin by client), one writer and many readers
    per program, per-client cancel, clean release when a client dies, idle shutdown, warm
    programs kept open for the next client.
- **`ghidra_session.py`**: a standard-library-only Python launcher, daemon manager and client
  (`connect()`), with no `.bat` or `.sh` launcher. Fast start with a class search cache and,
  on JDK 25+, an AOT cache.
- **Tests**: `examples/session_smoke.py` and `examples/daemon_tests.py`.
- **Headless build** (`gradle buildHeadless`, `gradle/hydra/headless.gradle`): an install
  without the window-only modules, the help, javadoc and Python stubs, and with a check that no
  module of the install depends on one it leaves out. The full build is still `gradle
  buildGhidra`.
- **Repository**: this README (Ghidra's original is `README-GHIDRA.md`), `NOTICE-HYDRA`, a
  security policy and contributor guide in `.github/`, issue and pull request templates, and CI
  (`.github/workflows/ci.yml`) that builds the headless install and runs both test suites.
- **Releases** (`.github/workflows/release.yml`): a tag `v<version>` builds the headless zip on
  Windows, runs both test suites on the unzipped install, and publishes the zip, `SHA256SUMS`
  and this file's section as a GitHub Release.
### Branches

- `main`: the above, on upstream `master`.
- `legacy-12.1.4`: the same module on Ghidra 12.1.4, kept for projects analysed with 12.1.4.
