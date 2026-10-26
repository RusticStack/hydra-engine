# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

A version is the Ghidra version a release is built on, then `-hydra.` and a counter (for
example `12.3-hydra.1`); its tag is `v` and the version. Releases are on
[GitHub](https://github.com/RusticStack/hydra-engine/releases).

## Unreleased

Not yet released; a release renames this heading to its version and names the upstream commit
it is based on.

### Added

- **Holder information in `busy`, `conflict` and `not_owner`** (HeadlessSession). The error
  details name who holds the project, program or lock: `holderInfo` (`client`, `name`,
  `harness`, `label`, `command`, `heldMs`; for another process, the user, host and time from
  Ghidra's project lock file and whether that process is alive), the project or program identity
  (`project`, `gpr`, `program` key, `path`, `sha256`), and `suggest`: `retry`,
  `fork_project` (with a ready `suggestion` request) where a working copy is the answer, or
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

### Changed

- The project files the upgrade cache keys and copies leave out Ghidra's transient files in a
  `.rep` (`tmp<n>.ps` pre-save copies of programs open for update, `tmp<n>.tmp`), so that a
  project another process has open for update keeps its identity until it is saved. Cache
  entries made before this are rebuilt once.
- The `busy` details of a program lock carry `program` as the program's key
  (`p1:/path`), like every other error, instead of its project path (now in `path`).

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
