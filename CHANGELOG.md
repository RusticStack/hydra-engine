# Changelog

What Hydra Engine adds on top of Ghidra. Ghidra's own changes are in its
[change history](Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md).

There are no releases yet. Version numbers will follow the Ghidra version a release is built on
(for example `12.3-hydra.1`).

## Unreleased

Based on upstream Ghidra `master` (12.3 DEV) as of 2026-10-21, commit `1640030366`.

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

### Branches

- `main`: the above, on upstream `master`.
- `legacy-12.1.4`: the same module on Ghidra 12.1.4, kept for projects analysed with 12.1.4.
