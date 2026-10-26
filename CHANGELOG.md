# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

A version is the Ghidra version a release is built on, then `-hydra.` and a counter (for
example `12.3-hydra.1`); its tag is `v` and the version. Releases are on
[GitHub](https://github.com/RusticStack/hydra-engine/releases).

## Unreleased

### Added

- **Holder information in `busy`, `conflict` and `not_owner`** (HeadlessSession). The error
  details name who holds the project, program or lock: `holderInfo` (`client`, `name`,
  `harness`, `label`, `command`, `heldMs`; for another process, the user, host and time from
  Ghidra's project lock file and whether that process is alive), the project or program identity
  (`project`, `gpr`, `program` key, `path`, `sha256`), and `suggest`: `retry`,
  `fork_project` (with a ready `suggestion` request) where a working copy is the answer, or
  `open_read_only`. `holder` stays a string as before; everything else is new fields.

### Changed

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
