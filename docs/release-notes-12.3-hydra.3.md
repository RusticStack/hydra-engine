# Hydra Engine 12.3-hydra.3: release notes (candidate)

Status: a local candidate, `release/hydra-3-rc`. Nothing is pushed, tagged or released. The
published release body is built by the release workflow from the `## 12.3-hydra.3` section of
`CHANGELOG.md` plus its download table (as for 12.3-hydra.2); this file is the longer record for
the owner: what is verified, what is not, and the commands to publish.

## What changed

12.3-hydra.3 is an upstream sync plus documentation and licensing changes. It adds no Hydra
feature and changes no Hydra behaviour.

- **Upstream sync.** Based on upstream Ghidra `master` (12.3 DEV) at commit
  `1b9e58a915cf867e106495eaa2a4b18eb4971c9d` (2026-10-27), merged with a plain merge commit: 0
  conflicts, 35 upstream commits (17 not merges), 29 files, none of which Hydra Engine changed.
  Decompiler (C++, so `decompile.exe` and `sleigh.exe` are rebuilt): GP-7212, GP-7414, GP-7423.
  Also GP-1 (`Range` is `long` based), GP-7418 (Ghidra URL encode and decode), GP-7416 (loader
  options from constructors deprecated in 12.2 keep headless `-loader-*` arguments) and smaller
  fixes.
- **Documentation and licensing.** README says Hydra Engine is a fork of Ghidra and qualifies its
  speed, write-safety and platform claims; a Platform and limits section; `NOTICE-HYDRA` rewritten
  as the Apache-2.0 section 4(b) notice of modifications; `NOTICE` and `NOTICE-HYDRA` now ship
  next to `LICENSE` in the engine zip and the client zip; CONTRIBUTING gets the upstream sync
  policy.
- **Not in this release:** the `Session.java` split (feat/session-extract) ships in 12.3-hydra.4.

## Verified

All on Windows 11 x64, JDK 25.0.4, Python 3.15, an NTFS volume (D:), from the zip produced by
`gradle zipHeadless`, unzipped, with the commit `a8a136b9ac` (the branch tip when these were run).

- **Build:** `zipHeadless` finished with exit 0 (log: `D:/Projects/Hydra/_logs/hydra3-rc/build2.log`).
  The native decompiler was built from the merged sources, but in this worktree Gradle took the
  compile results from the shared build cache (`FROM-CACHE`, same inputs as the earlier sync
  build), so they were not compiled again here. `hydra.version=12.3-hydra.3` was stamped into
  `hydra.properties` the way the workflow does and then removed from the tree; the stamp was read
  back from `HeadlessSession.jar` in the install.
- **Notices:** in the unzipped engine, `LICENSE`, `NOTICE` and `NOTICE-HYDRA` are at the install
  root, byte-equal to the repository's files. The release workflow's Unzip check (one top folder,
  then the three files) was run by hand against that tree and passed. `package-client.sh
  12.3-hydra.3` produced a client zip with the same three files (byte-equal) plus
  `ghidra_session.py` and `README.txt`.
- **Suites on the unzipped install** (fresh work and temp directories under
  `D:/Projects/Hydra/_logs/hydra3-rc/`): `session_smoke.py` exit 0, 34 checks passed;
  `contract_tests.py` exit 0, 5/5; `daemon_tests.py` exit 0, 31/31. The same three passed on the
  first zip as well (before the `headless.gradle` change below).
- **Decompile gate** (earlier stream, against 12.3-hydra.2): KotOR 8616/8616 functions identical on
  three decompile paths. x86 fixtures identical; one CRT `strncmp` function per x64 program
  differs, a GP-7212 improvement. No timing regression above run-to-run noise (interleaved A/B
  medians 3.40 ms and 3.37 ms; one raw back-to-back pair showed +14 to +16% and did not repeat).
- **DB format constants unchanged:** `ProgramDB` 33, `DataTypeManagerDB` 3, `DataTypeArchiveDB` 5,
  `ProgramUserDataDB` 1, `SlaFormat` 4, `LocalBufferFile` header 1.

`headless.gradle` fix: the docs branch copied the notices with `from(rootProject.projectDir) {
include ... }`. It worked (the files were in the install), and the build time did not show a
clear cost (assembleDistribution 31.1 s with it, 27.9 s with the change, one run each, not
conclusive). It is now `from(rootProject.files('NOTICE', 'NOTICE-HYDRA'))`, which names exactly
the two files; the build and the checks above were redone with this form.

## Not verified

- **ReFS.** Everything ran on NTFS. `fork_project` made a full copy (`cloned False`, 3.5 MB in
  13 ms); the block clone, and the speed-up of 3229f6e79f for the slow close of a temporary
  buffer file on ReFS, were not exercised in this build.
- **12.1.4 projects.** `legacy_overlay` and the older-format half of `upgrade_cache` were skipped
  (no project saved by Ghidra 12.1.4 was passed with `--legacy-project`).
- **GP-7423 and GP-7414** changed no output in the corpus; no regression seen, no improvement
  shown. KotOR is x86 only.
- **GP-7416** was checked only with `BinaryLoader -loader-baseAddr` (applied); no stock loader
  reaches the deprecated path.
- **The full upstream unit-test suite** was not run (three classes were: 55 tests passed).
- **The x64 golden baselines** still hold the old `strncmp` text; the 100% fixtures profile fails
  by one function per x64 program until they are re-recorded.
- **Linux and macOS** are not built or tested for this release.
- **The release workflow itself** was not run (no push). Its steps were reproduced by hand; the
  fetch-dependencies step was replaced by copying an existing `dependencies/` folder, and the
  `release` job (`gh` compare of the upstream commit, notes, publish) did not run. The local
  checks of its notes logic passed: the `## 12.3-hydra.3` heading exists, the section names
  commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`, and that commit is an ancestor of the branch.

## Platform and limits

- Windows x64 releases only; JDK 25 required (the install has no JDK); Python 3.10 or later.
- One daemon per state directory.
- `fork_project` is a block clone only on ReFS (Windows 11 24H2 or later); elsewhere a full copy,
  which `auto` refuses above `forkCopyLimitMb` (2048 by default).
- Writes are serialized and never corrupt a program, but are not collision-checked by default
  (last writer wins per value in shared mode; `expect` is opt-in per call).
- Changes are kept only by `save`.
- The base is a Ghidra development snapshot (upstream `master`), not a Ghidra release.

## Upgrading from 12.1.4 (one way)

A project saved by this build cannot be opened by Ghidra 12.2 or 12.1.4 (data type database
version 3). A 12.1.4 project opens read-only without being written, is upgraded in memory and is
served from the upgrade cache; writing it needs `"upgrade": true`, and that moves its databases
to the new format for good. Keep a backup, or work on a `fork_project` copy, when the original
must stay as it is. 12.3-hydra.2 projects open unchanged in 12.3-hydra.3 (no DB constant
changed; checked by a save and reopen in both directions, which is weak evidence because both
builds share the format). The `legacy-12.1.4` branch is frozen for projects that must stay on
12.1.4.

## Local record of the zips (not the release files)

The release zips are built by the release workflow on `windows-latest`, and their SHA-256 values
are in the release's `SHA256SUMS`. The two zips below were built here, on this machine, for
checking only. The engine zip is not byte-reproducible (the zip stores file times), so CI's
hash will differ; the client zip is built with fixed times and should match CI's if its inputs
match.

```
C83623F4F188E178600F7C4F68A9516647C00FFDF05F0F6EFE6F7C62E8509AF8  hydra-engine-12.3-hydra.3-win_x86_64.zip   (378,873,516 bytes; 3,324 entries)
da3a74372f2781a00525e7db49154f766f08bef7d1898c5c6e49191730bb4695  hydra-client-12.3-hydra.3.zip              (26,223 bytes)
```

Local copies: `D:/Projects/Hydra/_engines/hydra-3-rc-release/out/` (engine zip and its unzipped install),
`D:/Projects/Hydra/_logs/hydra3-rc/clientzip/` (client zip).

## Commands for the owner (not run)

Dry run first (builds and tests on CI, publishes nothing; needs the branch on GitHub):

```sh
git -C D:/Projects/Hydra/hydra-engine push origin release/hydra-3-rc
gh workflow run release.yml --repo RusticStack/hydra-engine --ref release/hydra-3-rc -f version=12.3-hydra.3
gh run watch --repo RusticStack/hydra-engine
```

Publish: merge into `main` (CONTRIBUTING: a merge, never a rebase), tag the merge, push the tag.
The workflow builds, tests the unzipped zip, and creates the release from the tag.

```sh
cd D:/Projects/Hydra/hydra-engine
git switch main
git merge --no-ff release/hydra-3-rc
git push origin main
git tag -a v12.3-hydra.3 -m "12.3-hydra.3"
git push origin v12.3-hydra.3
```

The earlier tags (`v12.3-hydra.1`, `v12.3-hydra.2`) are annotated, hence `-a`. The dry run uses
`--ref release/hydra-3-rc` on purpose: `release.yml` already exists on `main`, and the dry run tests
this branch's content before anything is merged. The merge into `main` adds one `--no-ff` merge
commit on top of the existing upstream merge; that is intended (merge, never rebase).

The Gradle comment in `headless.gradle` was reworded after the tested build (comment only; the code
line that was built and tested is unchanged).

After the release, check that it has the engine zip, the client zip and `SHA256SUMS`, and that
the release body names upstream commit `1b9e58a915cf867e106495eaa2a4b18eb4971c9d`. Do not merge
`feat/session-extract` before this release; it is for 12.3-hydra.4.
