# Contributing to Hydra Engine

Hydra Engine is upstream Ghidra plus a small set of additions (listed in `NOTICE-HYDRA`). Most
of what you see in this repository is Ghidra, and most of the work here is keeping the additions
small, tested and easy to carry across upstream syncs.

Ghidra's own contributor guide is [`CONTRIBUTING.md`](../CONTRIBUTING.md) at the root, and its
developer guide is [`DevGuide.md`](../DevGuide.md). They apply to the Ghidra code in this
repository; this file covers what is different here.

## What goes where

| Change | Where |
|---|---|
| The session daemon, its protocol, the launcher and client | `Ghidra/Features/HeadlessSession/` (Java in `src/`, `support/ghidra_session.py`, tests in `examples/`, documentation in its `README.md`) |
| The headless build | `gradle/hydra/headless.gradle` |
| Repository documentation, assets, templates, CI | `README.md`, `CHANGELOG.md`, `NOTICE-HYDRA`, `.github/` |
| The README's images | Generated, not drawn by hand: `.github/assets/src/` (`make_logo.py`, `make_diagram.py`; the session recording is `record_session.py` run against an install and the test program `hydra_demo.c`, then `render_terminal.py`) |
| A fix to Ghidra itself | Upstream first: a pull request to [Ghidra](https://github.com/NationalSecurityAgency/ghidra). Carry it here only if it is needed before upstream takes it, as its own commit that says so. |

Do not change an upstream Ghidra file when a new file can do the job: every changed upstream file
can conflict on every sync. Today the only upstream files changed are listed under "Upstream
sync" below.

## Build

You need a JDK (the version is `application.java.min` in `Ghidra/application.properties`; JDK 25
for `main`), Python 3.10 or later, and for the native parts (the decompiler, demanglers) a C/C++
toolchain: Visual Studio Build Tools on Windows, GCC or Clang on Linux and macOS. Gradle comes
from the wrapper.

```sh
# once: download the build dependencies into dependencies/
./gradlew -I gradle/support/fetchDependencies.gradle -DnoEclipse

# the headless install (the default)
./gradlew buildHeadless                     # -> build/dist/<ghidra_VERSION_DEV>/
./gradlew buildHeadless -PheadlessInstallDir=/path/to/install
./gradlew zipHeadless                       # -> build/dist/<name>_headless.zip

# the full Ghidra build, with the window, help and javadoc
./gradlew buildGhidra                       # -> build/dist/<name>.zip
```

On Windows use `gradlew.bat`. The build's file and folder names are Ghidra's (`ghidra_12.3_DEV`
and so on); Hydra Engine is the project's name, not the code's.

### The headless build

`buildHeadless` reuses Ghidra's own distribution tasks and leaves out:

- the modules in `HEADLESS_EXCLUDED_MODULES` (window-only features, and the debugger back ends
  that only the Debugger window launches) and the example extensions in
  `HEADLESS_EXCLUDED_EXTENSIONS`;
- help (indexing, building, and the help pages in the module jars), javadoc, JSON docs, Python
  type stubs, the markdown pass, the source zips and the user documentation in `docs/`;
- `ghidraRun`, `ghidraRun.bat` and the GhidraGo launchers;
- the zips and the other platforms: the result is an unzipped install for the platform you build
  on (`zipHeadless` zips it);
- the software bill of materials, `bom.json`, which opens every jar of the install one after
  another (`-PheadlessSbom=true` writes it).

On Windows, the headless build also leaves out `pdb.exe`, the PDB helper built against
Microsoft's DIA SDK. Ghidra's default PDB reader, "PDB Universal", is pure Java and does not use
it; the helper only works where the DIA SDK (`msdia140.dll`, shipped with Visual Studio) is
registered. To build it anyway, pass `-PwithPdbHelper`; it needs Visual Studio's C++ ATL
component (`atlcomcli.h`). `buildGhidra` always builds it, so the full build on Windows needs
ATL too.

The Python type stubs are left out too: they serve editors and type checkers, and PyGhidra and
headless Python scripts run without them.

Modules that mix window code and analysis code (Base, Docking, Decompiler, VersionTracking,
Debugger, which SystemEmulation needs, and so on) stay. The list was worked out from the module
graph: every module's project dependencies (`build.gradle`), its `Module.manifest`, and the
extension points its classes implement (analyzers, loaders, file systems, demanglers, script
providers, correlators), which Ghidra finds at run time without a project dependency. A module is
left out only if it implements none of those, has no scripts that headless users need, and no
module that stays depends on it.

`checkHeadlessModules` runs with every `buildHeadless` and fails if a module that stays depends
on one that is left out. If an upstream sync trips it, either move the module back in (remove it
from the list) or find out why the dependency appeared.

When upstream adds a module, it is in the headless install by default. Leave it there unless it
is clearly window-only.

### Build times

Measured on 2026-10-25 on Windows 11, 24 threads, 64 GB, JDK 25.0.4, Gradle 9.8.0 with
`--parallel`, 22 workers and the build cache, both builds in the same worktree and with
`pdb.exe` left out of both. The worktree was on a USB NVMe drive whose write speed fell to
24 MB/s during the session (1 GB/s on the internal drive at the same moment), and another build
and test run shared the machine for part of it, so wall times varied up to five-fold between
identical runs. They are ranges, not a benchmark:

| | `buildHeadless` | `buildGhidra` |
|---|---|---|
| Cold, `--no-build-cache`, after `clean` | 360 s alone; 969 s with a test run sharing the machine | 1926 s with another build running; 2137 s with a test run sharing the first 13 min |
| Actionable tasks | 524 | 836 |
| Nothing changed, run again | 153-960 s, almost all of it copying the install at the drive's speed | 283 s |
| `clean` afterwards | 23 s | 242-867 s (the javadoc and JSON doc trees) |

On GitHub's `windows-latest` runner, which has none of those problems, a cold `buildHeadless` (no
build cache) took 9 min 52 s, and the whole CI job, with both test suites, 15.5 min.

What does not depend on the drive: `buildHeadless` runs 312 fewer tasks (help, javadoc, JSON
docs, stubs, the window-only modules, the zips, other platforms) and writes a 639 MB install
instead of an 862 MB staging tree, a 538 MB zip and the doc trees. The long single-threaded tail of `buildGhidra` (`createJavadocs`, `createJsondocs`,
`zipJavadocs`, the stubs, the SBOM, `createInstallationZip`) is gone; what is left of the tail is
the copy into the install.

## Test

The tests start their own daemon instance with their own state directory, so they never touch
your daemon. They need two small executables and a DLL (any PE files; on Windows the CI uses
`choice.exe`, `whoami.exe` and `version.dll` from `System32`).

```sh
INSTALL=build/dist/ghidra_12.3_DEV            # what buildHeadless wrote
python Ghidra/Features/HeadlessSession/examples/session_smoke.py \
    --ghidra "$INSTALL" --work /tmp/hydra-smoke --binary A.exe --binary B.exe
python Ghidra/Features/HeadlessSession/examples/daemon_tests.py \
    --ghidra "$INSTALL" --work /tmp/hydra-daemon --exe A.exe --dll B.dll
```

`session_smoke.py` checks one client's whole flow and several clients' locking; `daemon_tests.py`
checks the daemon (two harnesses starting it at once, several projects, a killed client, a
killed daemon, fair scheduling, cancel, idle shutdown, warm programs, stdio). Both print one line
per step and exit non-zero on the first failure. CI runs both on Windows
(`.github/workflows/ci.yml`).

Ghidra's own unit and integration tests run as upstream describes (`./gradlew unitTestReport`
and so on); they need the full build.

## Commits and pull requests

- One change per commit, with a message that says what changed and why. Keep upstream merges,
  module changes, build changes and documentation changes in separate commits, so each one can be
  reverted or carried on its own.
- A pull request says how it was tested (OS, JDK, the test summary lines). A number in a README
  comes from a measurement, and the pull request says how it was taken.
- Protocol changes go in the module README in the same pull request.

## Upstream sync

`main` follows upstream Ghidra's `master`; `legacy-12.1.4` stays on Ghidra 12.1.4.

The policy:

- **Merge, never rebase.** `main` is public; upstream is brought in with `git merge`, so the
  history of both sides stays and a sync can be reverted as one merge commit.
- **One branch per sync**, `sync/upstream-YYYY-MM-DD`, cut from `origin/main`, never from an
  older local branch. It is merged into `main` only after CI passes on it.
- **The golden decompile diff is the gate.** Before and after the merge, decompile the same
  golden set (functions of binaries you own, small and large, in an analysed project) with the
  `main` build and with the sync branch's build, and compare the C. Any difference is explained
  (an upstream decompiler or analyzer change named in the merge) or the sync does not merge.
  Keep the golden set and its outputs outside the repository; never commit anything derived from
  a binary you do not have the right to redistribute.
- **Record the upstream commit.** The release's `CHANGELOG.md` section names the upstream
  commit it is based on (see "Releases"); for a sync that is not released yet, say it in the merge
  commit message.
- **Check the database format constants.** Compare `DB_VERSION` in `ProgramDB.java` (33 at the
  time of writing) and in `DataTypeManagerDB.java` (3) before and after the merge. If upstream
  raised either, projects saved by the new build cannot be opened by the old one and the upgrade
  cache starts over: say so in the compatibility statement of the next release.
- **`legacy-12.1.4` is frozen and end of life.** It is not synced, not released from and gets no
  new features; it exists only for projects that must stay on Ghidra 12.1.4. New work goes to
  `main`.

```sh
git remote add upstream https://github.com/NationalSecurityAgency/ghidra.git   # once
git fetch origin upstream
git switch -c sync/upstream-YYYY-MM-DD origin/main
git merge upstream/master                  # a merge, never a rebase: main is public
./gradlew buildHeadless                    # then run both test suites
```

Push the branch, let CI pass, then merge it into `main`. Note the upstream commit in
`CHANGELOG.md`.

### The scheduled sync

[`upstream-sync.yml`](workflows/upstream-sync.yml) does the first half of this by itself. Weekly
(Wednesdays, 05:23 UTC) and on demand it fetches upstream `master`; if there is nothing new it
stops. Otherwise it cuts `sync/upstream-YYYY-MM-DD` from `main`, **merges** `upstream/master` into
it (never a rebase), runs `buildHeadless`, the three session suites (`session_smoke.py`,
`daemon_tests.py`, `contract_tests.py`) and the golden diff (`characterization_tests.py`, protocol
2 and 3: the recorded replies must be byte-identical), and opens a pull request whose body carries
the upstream shortlog, the files changed on both sides and the `DB_VERSION` comparison.
`gh workflow run upstream-sync.yml -f dry_run=true` does everything except the push and the pull
request. The workflow never merges the pull request and never pushes to `main`.

Two things make the job fail, and both are merged by hand:

- **The patched-core-file guard.** [`hydra-touched-files.txt`](hydra-touched-files.txt) lists the
  upstream Java classes we patch (the five in the table below). If upstream changed any of them
  since the last sync, the report names it and the job fails after the tests have run. A new patch
  to an upstream class is added to that file, to `NOTICE-HYDRA` and to the table in the same commit.
  `scripts/upstream-sync-report.sh <base> <upstream>` makes the report locally;
  `scripts/test-upstream-sync-report.sh` tests the guard on a throwaway repository.
- **A merge conflict.** The job lists the files and stops.

What the workflow does not check, and a person must before merging the pull request: the decompile
golden set above (it stays outside the repository), and the Actions page for a new upstream workflow.

### What conflicts, and how to resolve it

Hydra Engine changes only these upstream files, so these are the only places a sync can
conflict:

| File | Why it conflicts | Resolution |
|---|---|---|
| `README.md` | Upstream edits its README; ours replaced it, and upstream's text lives in `README-GHIDRA.md`. | Keep ours: `git checkout --ours README.md`. Then bring upstream's new text across unchanged: `git show upstream/master:README.md > README-GHIDRA.md`, and `git add README.md README-GHIDRA.md`. |
| `build.gradle` | Our one line at the end (`apply from: 'gradle/hydra/headless.gradle'`); a conflict only if upstream also appends at the end. | Keep upstream's change and our line, ours last. |
| `.github/ISSUE_TEMPLATE/bug_report.md`, `feature_request.md`, `question.md` (removed; our issue forms are new files) | Upstream rarely edits its templates. | Keep them deleted (`git rm`). |
| `Ghidra/Framework/DB/.../LocalBufferFile.java`, `LocalManagedBufferFile.java`, `Ghidra/Framework/FileSystem/.../LocalDatabaseItem.java`, `VersionedDatabase.java`, `Ghidra/Framework/SoftwareModeling/.../SleighLanguageFile.java`, and the added `VersionFileCheck.java` | The small changes (module README, "Changes outside this module"), each with a one-line Hydra Engine comment above `package`. | Merge by hand, keeping both changes and the comment; rerun `import_write_kill` and the two test suites. |
| `gradle/distributableGhidraModule.gradle` | Two `exclude` lines in the `support` copy. | Keep upstream's change and our two lines. |
| `.gitattributes` | Three lines at the end. | Keep upstream's change and ours. |

Every file in this table, and any other upstream file we change, is listed in `NOTICE-HYDRA`
(Apache-2.0 section 4(b)); update it in the same commit.

Files we only add (`gradle/hydra/`, `.github/CONTRIBUTING.md`, `.github/SECURITY.md`,
`.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/upstream-sync.yml`,
`.github/hydra-touched-files.txt`, `.github/assets/`, `NOTICE-HYDRA`, `CHANGELOG.md`,
`README-GHIDRA.md`, `Ghidra/Features/HeadlessSession/`) cannot conflict, unless upstream adds a
file with the same path.

Things that do not conflict but can still break:

- **The headless build** uses upstream task names (`assembleDistribution`,
  `assembleDistribution_<platform>`, `zipExtensions`, `indexHelp`, `buildHelpFiles`,
  `buildModuleHelp`, `buildGlobalMarkdown`, `createJavadocs`, ...). If upstream renames one,
  `buildHeadless` fails or ships more than it should: compare the install's size and module list
  with the previous one. `checkHeadlessModules` catches new dependencies on excluded modules.
- **Upstream workflows** (`.github/workflows/build-ghidra.yml` and the others) stay as upstream
  has them, so they never conflict. `Build Ghidra` (a full build on every push) is disabled in
  this repository's Actions settings, not in the file; the full build runs weekly and on demand
  from `ci.yml`. After a sync, check `gh workflow list` for a new upstream workflow and disable it
  the same way if it duplicates ours.
- **The module** builds against Ghidra's API; a sync that changes an API it uses shows up as a
  compile error in `HeadlessSession` or a failure in the two test suites.
- **The launcher** (`ghidra_session.py`) rebuilds Ghidra's classpath from the module layout;
  upstream changes to `GhidraLauncher`'s ordering or `launch.properties` need the same change
  there.

## Releases

A version is the Ghidra version of the build (`application.version` in
`Ghidra/application.properties`), `-hydra.` and a counter that starts at 1 for each Ghidra
version: `12.3-hydra.1`, `12.3-hydra.2`, then `12.4-hydra.1`. The tag is `v` and the version.

1. Sync with upstream first (above), so a release is on the latest `master`, and let CI pass on
   `main`.
2. In `CHANGELOG.md`, turn the `## Unreleased` entries into a new `## <version>` section below
   an emptied `## Unreleased`: the date, the upstream commit it is based on, written as
   ``commit `<40-hex sha>` `` (the release workflow refuses a section without one, or with a
   commit that is not in the tag's history), a summary for integrators, the compatibility
   statement (protocol version, `minClient`, `CLIENT_VERSION`, project formats, platforms tested),
   the known limits, and what changed. If the client gained something since the last release,
   bump `CLIENT_VERSION` in `ghidra_session.py` (and `MIN_CLIENT` in `HydraInfo.java` only when
   older clients can no longer drive the engine). Commit it to `main` and let CI pass on that
   exact commit.
3. Dry run, optional: `gh workflow run release.yml --ref main -f version=<version>` builds and
   tests every platform and uploads the notes it would publish (`release-dry-run-notes`), without
   publishing.
4. Tag and push: `git tag v<version> && git push origin v<version>`. `release.yml` builds the
   headless zip on Windows (`hydra-engine-<version>-win_x86_64.zip`), unzips it and runs
   `session_smoke.py`, `daemon_tests.py` and `contract_tests.py` on it, and only if all pass
   packages the client (`.github/scripts/package-client.sh`: `hydra-client-<version>.zip`) and
   publishes the release with both zips, `SHA256SUMS` and the changelog section, followed by a
   table of what was tested where.
5. Check the release page: both zips there, their SHA-256 matching `SHA256SUMS`; unzip the
   engine and run `session_smoke.py` against that install (not the source tree), and run the
   packaged client's `python ghidra_session.py version`, which must print the release.

Releases are Windows-only, like CI. The build matrix in `release.yml` takes more platforms
(`ubuntu-latest` as `linux_x86_64` and `macos-latest` as `mac_arm_64` passed in a dry run), but
their test steps then need PE files as test inputs, which their runners do not have; a platform
is added only together with CI, and never ships untested.

## Cadence and support

These numbers are **defaults, not commitments**: the owner has not yet decided them (decision N9).
Until that is done they say what the maintainers aim at, nothing stronger, and no release note may
promise more than this section does.

| | Default |
|---|---|
| Upstream sync | Checked weekly by `upstream-sync.yml`; a sync pull request is reviewed within 14 days of being opened. |
| Releases | When there is something to ship, and always after a sync whose changes reach the build. There is no fixed release day. |
| Supported versions | The newest `<Ghidra version>-hydra.<n>` only. The version before it gets fixes for a security problem for 30 days after a newer one is published. `legacy-12.1.4` is end of life (see "Upstream sync"). The table is in [`SECURITY.md`](SECURITY.md). |
| Security fix time | A confirmed vulnerability in code this repository adds: a fix in `main` within 30 days of the report, released with it. A vulnerability fixed upstream: merged and released within 30 days of the upstream fix. See `SECURITY.md`. |
| Which upstream line | `main` follows upstream Ghidra `master` (12.3 DEV at the time of writing), not a stable release line. A move to a stable line is a decision for the owner and is recorded in `CHANGELOG.md` when taken. |

The Hydralysis companion project pins an engine release and follows the engine's releases: it
moves to a new `hydra.<n>` after that release's session suites have passed against it, not
automatically.

## Code style

Java follows Ghidra's style (`eclipse/` has the formatter, `GhidraDocs/GhidraCodingStandards`
the rules). Python in `support/` is standard library only, 3.10+, and must stay that way: it is
copied into installs and run with whatever Python the user has.

## Licence

Contributions are under the Apache License 2.0, the licence of the repository (`LICENSE`).
