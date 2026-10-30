# Headless Session

`analyzeHeadless` is a command about one program file: it opens (and locks) one project, runs
pre/post scripts against the programs that `-process`/`-import` select, and exits. The headless
session keeps the process up instead: you open a project, see what is in it, pick a program,
switch to another, keep working, save, and the process stays.

There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by Ghidra 12.2
or 12.1.4. The session is a shared service per state directory and instance: one long-lived JVM,
driven by JSON lines over an authenticated loopback socket (or stdio), that:

- serves **several projects at once**, each opened in place by its `.gpr`, its folder, or a
  parent folder: read-only without touching the project, or writable when asked;
- serves **several clients at once** (several agent harnesses, tools, MCP servers; tested with up
  to 4 clients), which find it through an endpoint file in the state directory and start it if it
  is not running;
- lists folders and programs, with each program's SHA-256, without opening them;
- opens and switches programs, also inside folders, **without importing**;
- imports any format a Ghidra loader accepts (PE EXE and DLL, ELF, Mach-O, raw, ...), never twice
  for the same SHA-256 in a project;
- runs auto-analysis on request, decompiles, renames, comments, saves;
- runs any GhidraScript (Java, or Python through a script provider) with arguments;
- lets several clients change things at once: several writers in one project, several writers
  of one program (shared mode, with an author journal and `expect` to detect lost updates), a
  private **overlay** per client over a program others read, and **working copies**
  (`fork_project`, a block clone on ReFS) of a project others keep reading;
- notices when another process saves a project it serves read-only, and reopens it for all its
  clients at once (`refresh`);
- imports in parallel (`maxImports`), with a visible, cancellable queue;
- shares work: per-program read/write locks, two lanes (native commands stay in the quick lane
  while imports and analyses run in the long lane), per-client (and per-label) cancellation of
  requests waiting for a slot and of cooperative scripts, and, when a client disconnects, its
  requests cancelled and its uncommitted changes rolled back when its running request ends;
- stays up (or stops after an idle time you choose).

It is one new module, plus five small changes to Ghidra classes and one added class, found by the
session's measurements and tests (see "Changes outside this module"). No launcher is changed, and there are no `.bat`, `.sh`
or PowerShell launchers: `support/ghidra_session.py` (Python 3.10+, standard library only, any
OS) starts the JVM itself.

## Quick start

```
python <ghidra>/Ghidra/Features/HeadlessSession/support/ghidra_session.py ensure
python <ghidra>/Ghidra/Features/HeadlessSession/support/ghidra_session.py status
```

Each `ghidra_session.py call <cmd> ...` is one request from a new client that disconnects when it
returns, so what it opened does not carry over: `call open_project` and then `call decompile`
answers `no_project`. For a sequence, keep one connection.

From Python (put `support/` on `sys.path`, or copy the one file):

```python
import ghidra_session as gs

with gs.connect(client="my-tool", harness="claude-code") as s:    # starts the daemon if absent
    p = s.call("open_project", path=r"C:/re/Game")                 # read-only view, no lock
    s.call("open_program", path="game.exe")                       # or "/folder/game.exe"
    print(s.call("decompile", address="rva:0x5d53a0")["c"])
```

Any other language speaks the same JSON lines to the port in the endpoint file (below).

## The launcher: `support/ghidra_session.py`

It does what `launch.bat`/`launch.sh` and `LaunchSupport` do, without a shell and without the
three extra JVMs `LaunchSupport` costs on every start:

- **Install:** the install this file belongs to, else `--ghidra`, else `GHIDRA_INSTALL_DIR`.
- **JDK**, first that fits the install's Java range and is a JDK (not a JRE): `--java` or the
  config's `java`, `GHIDRA_SESSION_JAVA_HOME`, `launch.properties`' `JAVA_HOME_OVERRIDE`,
  `JAVA_HOME`, the JDK Ghidra's own launcher saved for this version (`java_home.save`), `java` on
  `PATH`. The version is read from the JDK's `release` file, without starting a JVM.
- **JVM options:** `support/launch.properties` (`VMARGS`, `VMARGS_<OS>`, `ENVVARS`), then heap,
  GC, `java.io.tmpdir` and your extra options. JVM log messages go to stderr, never to the
  protocol channel. Compact object headers (`-XX:+UseCompactObjectHeaders`, a product option
  since JDK 25) come from Ghidra's `launch.properties`, so every daemon has them; `vmargs`
  `-XX:-UseCompactObjectHeaders` turns them off (your options come last and win), and the AOT
  cache then gets a file of its own. Measured on JDK 25.0.4.1 (Temurin), import and analysis of
  `ntdll.dll` (2.5 MB) in a daemon with its AOT cache, 3 runs each: about 4% less process CPU
  (95 against 100 s), about 9% less peak heap after a collection (262 against 289 MB) and the
  same wall time as with them off; without an AOT cache it took about 5% more CPU (101 s). The
  daemon suite at 22 cores, 2 runs each, had the same failures either way.
- **Classpath**, two modes:
  - `fast` (default): the classpath that `GhidraLauncher` would build, rebuilt from the module
    layout (patch dir, every module's `lib/` jars ordered by module type and name, extensions
    last, fat jars at the end; identical, entry for entry, to what `GhidraLauncher` computes,
    except that a `patch` directory holding only its README is left out because an AOT cache
    refuses a non-empty directory on the classpath; 158 entries on master),
    passed in a Java `@argfile` (a full classpath can exceed Windows' command-line limit), with
    the JVM's default class loader and the entry point `SessionMain`. Without a custom system
    class loader the JVM can use an **AOT cache** for Ghidra's classes, which
    `GhidraClassLoader` rules out (that is why `launch.properties` says `-Xshare:off`).
  - `standard`: exactly Ghidra's own launch (`Utility.jar`, `ghidra.Ghidra`, `GhidraClassLoader`,
    `-Xshare:off`), minus the shell and `LaunchSupport`.
- **Class search cache:** Ghidra scans every jar for extension points on each start. The result
  depends only on the classpath and the modules' `ExtensionPoint.manifest` files, so the session
  stores it (`<state>/classcache/`) with the size and time of every input and reuses it while all
  are unchanged; anything changed means a normal search and a new cache.
- **AOT cache** (JDK 25+): `ghidra_session.py aot [--project <a small project>]` runs a training
  session (start-up, a project, a program, a few decompiles) with `-XX:AOTCacheOutput`; fast-mode
  starts then use it automatically. It is keyed by the JDK, the install and every classpath jar's
  size and time, so an update or another JDK just runs without it until you rebuild it, and by the
  JVM options a cache must match (the garbage collector, compact object headers, compressed
  pointers, which a heap of 32 GiB or more turns off): the JVM refuses a cache recorded with other
  ones and silently runs without it, so each set gets its own file.
- **Deferred start-up:** what no query needs is started on a background thread once the session
  is ready: the language service (every program open needs it), the default TLS context (master
  loads every trusted CA certificate of the OS and of Java for it) and the OSGi framework that
  compiles scripts. `script`, `import` and `analyze` wait for it first.
- **Upgrade cache:** see "Programs saved by an older Ghidra" below.

| Command | Does |
|---|---|
| `ensure` | Starts the daemon if it is not running; prints its endpoint (without the token). |
| `status` | The running daemon: projects, programs and who uses them, clients, scheduler, memory, launch info. |
| `call CMD key=value...` | One request through the daemon, as a new client that disconnects afterwards (nothing it opens carries over to the next `call`); values are JSON when they parse (`writable=true`). |
| `stop [--force]` | Asks the daemon to shut down (refused while other clients are connected, unless `--force`). |
| `kill` | Kills the daemon's JVM without a shutdown (wedged daemon, tests). |
| `version` | Prints this client's `CLIENT_VERSION`, protocol and release (no daemon needed). |
| `serve` | Runs the daemon in the foreground (for a service manager). |
| `stdio [ARGS...]` | A private session on this process's stdin/stdout; no daemon, no socket. |
| `aot [--project P] [--program X]` | Builds the AOT cache. |
| `command [ARGS...]` | Prints the Java command line it would run. |
| `config` | Prints the effective configuration, JDK and install. |

Global options: `--ghidra`, `--state`, `--instance`, `--java`, `--max-heap`, `--gc`, `--mode`,
`--tmpdir`.

### Configuration

Lowest to highest: defaults, `<state>/config.json`, environment, command-line options.

| Key (`config.json`) | Environment | Default | Meaning |
|---|---|---|---|
| `java` | `GHIDRA_SESSION_JAVA_HOME` | discovered | JDK home. |
| `maxHeap` | `GHIDRA_SESSION_MAXMEM` | a quarter of RAM, 2-31 GiB | `-Xmx`. G1 only takes what it needs and returns idle memory. |
| `minHeap` | | `512m` | `-Xms`. |
| `gc` | `GHIDRA_SESSION_GC` | `g1` | `g1` (with string deduplication and periodic uncommit), `zgc`, `parallel`, `default`. |
| `vmargs` | `GHIDRA_SESSION_VMARGS` (space-separated) | `[]` | Extra JVM options, last. |
| `tmpdir` | `GHIDRA_SESSION_TMPDIR` | the JVM's | `java.io.tmpdir`: where Ghidra keeps unsaved database buffers. Put it on a fast disk with room. |
| `mode` | `GHIDRA_SESSION_MODE` | `fast` | `fast` or `standard` (above). |
| `aot` | `GHIDRA_SESSION_AOT` | `auto` | `auto`: use the AOT cache when one exists; `off`. |
| `classCache` | | `true` | The class search cache. |
| `idleTimeout` | `GHIDRA_SESSION_IDLE_TIMEOUT` | `0` | Seconds without clients before the daemon exits; `0`: stay up. |
| `keepWarm` | `GHIDRA_SESSION_KEEP_WARM` | `3600` | Seconds an unused read-only program or project stays open, so the next client gets it at once with warm decompilers; `0`: close at once. |
| `maxQuick` | | CPU count | Concurrent quick requests. |
| `maxLong` | | `max(8, CPUs)` | Concurrent long requests (analyze, import, script; `save`, `fork_project`, `refresh`, `reopen` and `promote_overlay` on a protocol 2 connection; protocol 3 runs those in the maint lane). Hydra Engine 12.3-hydra.3 and earlier: CPU / 4, at least 2. |
| `maxImports` | | CPU / 4, between 1 and 4 | Concurrent imports, in any projects (see "Parallel imports"). Each running import also holds a long slot, so at most `min(maxImports, maxLong)` run at once. Each holds its whole program in memory until it is saved: budget about 0.7 GB of heap per 25 MB PE. |
| `scriptPath` | | `[]` | Extra GhidraScript directories. |
| `log` | | `<state>/<instance>.log` | The daemon's log (Ghidra's log and stderr). |
| `upgradeCache` | `GHIDRA_SESSION_UPGRADE_CACHE` (`off`, `false`, `0`: off) | `true` | Serve read-only opens of programs saved in an older database format from an upgraded copy (below). |
| `upgradeCacheDir` | `GHIDRA_SESSION_UPGRADE_CACHE_DIR` | `<state>/upgrade-cache` | Where those copies live; best on the same volume as the projects (a block clone there costs nothing). |
| `forkCopyLimitMb` | `GHIDRA_SESSION_FORK_COPY_LIMIT_MB` | `2048` | `fork_project` in `auto` mode refuses a full copy (one the file system cannot block-clone) larger than this; `"mode": "full"` copies anyway. |
| `settingsDir` | `GHIDRA_SESSION_SETTINGS_DIR` | `auto` | Ghidra's per-user settings dir of the daemon (its OSGi `felixcache` and compiled script bundles, which every JVM of a user shares and contends for). `auto`: its own, `<state>/settings/<instance>` (the user's `Extensions` are linked into it); `shared`: the user's, as Ghidra's launcher chooses; or a directory. Passed as `-Dapplication.settingsdir`, so it also reaches the launch routes without an environment; a `-Dapplication.settingsdir` in `vmargs` or `launch.properties` wins. The first script of a daemon compiles into an empty cache. |

#### Engine settings (protocol 3 release)

Further settings are not options of the launcher: every entry of the `engine` object of `config.json`
is passed to the daemon as a repeatable `-set key=value`, and each part of the engine reads its own keys
(`Settings.java`). A value that does not parse as the type its reader expects stops the daemon at start-up with
a message that names the key; an unset key reads as its default. Only keys that the engine reads today are
listed. The design text for keys that belong to packages not yet part of the release is in
`PROTOCOL-3.md` 3.7; they are not settings of this release until their package is.

| Key | Default | Meaning |
|---|---|---|
| `maintSlots` | 4 | Slots of the maint lane (protocol 3 `save`, `fork_project`, `refresh`, `reopen`, `promote_overlay`). |
| `maxLong` | `max(8, CPUs)` | Same as the `maxLong` option above. |
| `quickScriptMaxS` | 60 (at most 120) | Longest `timeout` for a script that asks for `lane:"quick"`. |
| `maxRunningPerKey` (and `.quick`, `.long`, `.maint`) | quick `max(1, slots / 2)`, long `max(1, slots - 1)`, maint 1 | The work-conserving cap of running requests per connection while another connection waits. |
| `cleanupGraceS`, `abandonWaitS` | 15, 5 | Release of a dead client: seconds its requests may keep running, then seconds to wait for the interrupt before the client is released regardless. |
| `requireExpect` | false | An edit on a program with shared writers must carry `expect`. |
| `requireBackupForUpgrade` | true | The upgrade gate: a writable upgrade of a canonical project needs a valid backup. |
| `orphanKeepS` | 0 (never) | When above 0: after this many seconds the unsaved edits of a shared program whose last writer died are written to `<state>/recovery/` and discarded. |
| `starveMs` | 30000 | A lane with a request waiting longer than this reports `starving` in `status`. |
| `writeStallMs` | 5000 | A client that does not read its socket for this long is disconnected. |
| `scriptMaxS`, `scriptGraceS` | 600, 5 | Wall-clock budget of a script, and the seconds a script that ignores its cancel may run on before it is quarantined. |

#### Stamping a local build

The build tool does not stamp a release version. The engine reports `hydraVersion` from
`src/main/resources/hydra.properties`, which is empty in the tree, so a plain `gradle buildHeadless` or
`gradle zipHeadless` says `<Ghidra version>-hydra.dev` and Hydralysis classifies it as a stock Ghidra. The
release workflow writes the stamp before it builds. To get the same in a local build (in bash or
PowerShell 7; Windows PowerShell 5.1 writes UTF-16 with `>`, which the build ignores, so use
`Set-Content -Encoding utf8` there):

```
echo hydra.version=12.3-hydra.4 > Ghidra/Features/HeadlessSession/src/main/resources/hydra.properties
gradle zipHeadless            # or buildHeadless
git checkout -- Ghidra/Features/HeadlessSession/src/main/resources/hydra.properties
```

Restore the file afterwards: the tree must keep it empty (the release workflow's dry run fails when the zip it
built does not carry the stamp it wrote, and `tools/bump_hydra.py` of Hydralysis refuses a zip without it).

The state dir is `--state`, else `GHIDRA_SESSION_HOME`, else per user:
`%LOCALAPPDATA%\GhidraSession` (Windows), `~/Library/Application Support/GhidraSession` (macOS),
`$XDG_STATE_HOME/ghidra-session` or `~/.local/state/ghidra-session` (Linux). It is created
owner-only on POSIX; on Windows it inherits the per-user ACL of its parent.

## The shared daemon

One daemon per state directory and **instance** (default `default`); Hydralysis uses its own
instance and data root. Its files in the state dir:

| File | Written by | Purpose |
|---|---|---|
| `<instance>.json` | the JVM, atomically, once it listens | `{protocol, pid, host, port, token, install, ghidra, java, launch, ...}`. Removed at a clean exit. |
| `<instance>.lock` | the JVM, held for its whole life | An exclusive OS file lock: proves the JVM is alive (a killed JVM's lock is released by the OS), and a second daemon of the instance exits at once (code 3). |
| `<instance>.start.lock` | the launcher, while starting it | Two harnesses that find no daemon at the same moment start only one: the second waits on this lock, then finds the first one's daemon. |
| `<instance>.log` | the JVM | Rotated at 32 MiB. |

`connect()` / `ensure`:

1. If the endpoint file exists and the instance lock is held, connect and send `hello` with the
   token. Done.
2. Otherwise take the start lock, check again, remove a stale endpoint file (a killed JVM leaves
   one; it is never dialled, because on Windows a connect to a closed port is retried for about
   2 s), start the JVM detached (its own process group, outside the caller's job object when
   allowed, so it outlives the harness that started it), and wait for its endpoint.
3. A daemon of another install, or another protocol version, is refused with a clear error: stop
   it or use another `--instance`.

**Security.** The socket binds loopback only (non-loopback binds are refused); the first request
must be `hello` with the 256-bit token from the endpoint file, compared in constant time. The
endpoint file is owner-only. Anyone who can read your state dir can drive the daemon, with your
rights, as anyone who can run your Python can.

**Memory.** The default heap ceiling is a quarter of physical memory, up to 31 GiB (compressed
pointers). A large analysed program, such as a 1.5 GB project with 240,000 functions, needs a few
GiB once opened; several projects add up. G1 grows the heap only as needed and returns idle
memory every 5 minutes. `status` reports `memory.usedMb`/`maxMb`.

**Lifecycle.** The daemon stays up until `stop`, `kill`, or `idleTimeout` seconds without
clients. Read-only programs and projects that nobody uses stay open for `keepWarm` seconds;
writable projects close (and release their lock) as soon as their last user leaves.

## Read-only view, writable project

By default a project is opened as a read-only view: as
`new DefaultProjectData(locator, false, false)`, which takes **no project lock** and opens every
file system read-only. Nothing in the project is written: not a lock file, not an index, not a
timestamp. Several sessions, and other processes, can read the same project at the same
time, and there is no need to copy the project first.

`analyzeHeadless` cannot do this. It always opens the project through `DefaultProject`, which
calls `new DefaultProjectData(locator, true, ...)` and locks the project, even with `-readOnly`;
`-readOnly` only skips the save (`HeadlessAnalyzer.openProject` and its `HeadlessProject`;
`processFileNoImport` opens the program with `getDomainObject` and does not save it;
`DefaultProject.java:119`).

With `"writable": true` the project is opened with its lock.
Only one process can hold it: a writable open while another process (another Ghidra process,
`analyzeHeadless`, another daemon) holds it gets `conflict` naming the lock file and its holder.
Inside this daemon the writable project is one instance that its clients share ("Several
clients").

A read-only view does not see changes another process saves to the project after it was opened;
its clients are told (`stale`, below), and `refresh` reopens it for all of them.

### Revisions and `refresh`

Every project and program has a **revision**, a 16-hex-digit fingerprint of what is saved:

- **Project revision**: every file of the `.gpr` and `.rep` by relative path, size and
  modification time, plus the SHA-256 of every file up to 1 MiB (the `.gpr`, property and index
  files): the identity the upgrade cache keys by, without the project's location and this
  Ghidra's version, and without `<name>.rep/projectState` (tool state Ghidra rewrites
  when a writable project closes) and Ghidra's transient pre-save files. Ghidra writes its large
  database files whole, as new versions, never in place, so their size and time identify them.
  Two daemons, and a copy with its files' times kept, agree on it.
- **Program revision**: its project path and the size, time and version of its stored file,
  taken when it is opened and after every save here.

`open_project`, `project`, `projects` and `status` show a project's `revision` (for a read-only
view: what it was opened from; for a writable project: what is saved now), `diskRevision` (what
is saved now, read at most once a second), `stale` and `generation` (bumped by every refresh).
`open_program`, `info` and `status` show a program's `revision`, its `projectRevision` and
`generation`; `save` answers the new `revision` and `projectRevision`.

**Stale views.** Every answer to a client (but `ping`, `status` and `cancel`) carries, next to
`result`, what changed under it:

```json
{"id": 12, "ok": true, "result": {...}, "ms": 3,
 "stale": [{"project": "p1", "revision": "5b0c9e2d81f4a7c3", "diskRevision": "e1d24f6b9a03c8d7", "suggest": "refresh"}]}
{"id": 13, "ok": true, "result": {...}, "ms": 2,
 "refreshed": [{"project": "p1", "generation": 2, "from": "5b0c9e2d81f4a7c3", "revision": "e1d24f6b9a03c8d7"}]}
```

`stale` lists the client's read-only views whose project another process saved since they were
opened: their answers still come from the old revision. `refreshed` lists, once, the projects
another client refreshed since this client last heard: what it cached from them before came from
the older revision. (`ghidra_session.py`: `call_raw` returns the whole response; `last_response`
holds the last one.)

**`refresh`** (or `reopen`) `{project}` reopens a read-only view on what is saved now **without
its clients leaving**. The new view is opened first, outside every lock; then, under the
project's exclusive lock (requests already running finish first, new ones wait, so nobody sees
half of the switch), every program clients use is reopened from it under the same key (its
overlays are rebuilt from their logs, see "Overlays"), programs nobody uses are closed, and the
old view is closed:

```json
{"cmd": "refresh", "project": "p1"}
{"project": "p1", "refreshed": true, "from": "5b0c9e2d81f4a7c3", "revision": "e1d24f6b9a03c8d7",
 "generation": 2, "programs": [{"program": "p1:/game.exe", "revision": "0d8a1f...", "action": "reopened", "newRevision": "77c2e0..."}],
 "ms": 140, "info": {...}}
```

A program the new revision no longer has is closed for its users (`action: "removed ..."`).
Unchanged (`"force": true` reopens anyway) or writable (this daemon holds its lock, so it always
shows what is saved) projects answer `"refreshed": false` with the `reason`.

**Forks and a newer master.** A fork's sidecar keeps `baseRevision`: the master's revision when
the fork was made. A fork starts at that revision itself (the copy keeps the files' times), and
moves on with its first save. So:

- master `revision` == fork `baseRevision`: the master has not changed since the fork; anything
  derived from the fork's base still describes the master.
- master `revision` != fork `baseRevision`: the master was saved since (for example a newer
  analysis was promoted into it); overlays and annotations made against the base must be
  re-checked (replayed) against it.
- fork `revision` == master `revision`: the two hold the same saved files (a promotion that
  copied the fork over the master with its times kept gives this).

Revisions compare saved state, not programs' meaning: any save changes them.

### Working copies: `fork_project`

A read-only view lets several clients read a project, and clients of this daemon may
write it together (each program with its owner or its shared writers), but whatever they save
is the project everyone reads. A client that wants to change things without changing the master
others keep reading, or that wants a program to itself for long, heavy work, forks the project
into a **working copy** of its own:

```json
{"cmd": "fork_project", "project": "p1", "path": "C:/work/agent-a", "writable": true, "mode": "auto"}
```

```json
{"project": "p2", "path": "C:/work/agent-a", "gpr": "C:/work/agent-a/Game.gpr", "name": "Game",
 "writable": true, "baseRevision": "9c1e0f6a2b7d4e15",
 "source": {"project": "p1", "gpr": "C:/re/Game/Game.gpr", "name": "Game",
            "revision": "9c1e0f6a2b7d4e15", "writable": false, "fork": false},
 "mode": "auto", "method": "clone", "cloned": true,
 "clonedBy": "free space (3702784 of 1560659022 bytes used)",
 "bytes": 1560659022, "files": 10, "copyMs": 204, "freeSpaceUsedBytes": 3702784, "depth": 1,
 "sidecar": "C:/work/agent-a/Game.fork.json", "ms": 275, "info": {...}}
```

- `project`: the source, an open project's id or a project path (the client need not have
  joined it). `path`: a folder for the fork (it keeps the source's name, or `name`), or a
  `.gpr` path. An existing project there is never overwritten (`conflict`).
- **The source is only read.** Its read-only views stay open and in use; nothing in the source
  is written. The fork is opened for the caller, writable unless `"writable": false`, and is an
  ordinary project from then on (`close_project` it; deleting it is the caller's business).
- **The copy** is the one the upgrade cache makes: the `.gpr` and every file of the `.rep`, never
  the lock files or Ghidra's transient pre-save files, with the platform's copy. On Windows 11
  24H2 and later that block-clones on ReFS (a Dev Drive): the fork shares the source's blocks
  until either side writes. Elsewhere it is a full copy. `mode`:
  - `auto` (default): clone where possible; otherwise a full copy up to `forkCopyLimitMb`
    (default 2048 MB), and above it `conflict` with `reason: "too_large"` and the cost (`bytes`,
    `files`, file systems, free space) so that the caller can decide.
  - `copy-on-write`: only a clone; otherwise `conflict` with `reason: "no_copy_on_write"` and the
    cost.
  - `full`: copy whatever it costs (`maxCopyMb` on the request overrides the limit for `auto`).
  `cloned` says whether it was a clone: from the free space the copy used when the fork is
  64 MiB or more, else from the file system (`clonedBy` says which). Other copy-on-write file
  systems (Btrfs, XFS, APFS) are not claimed; there a fork counts as a full copy.
- **A source someone writes is refused**, because its saved state may change under the copy:
  open writable in this daemon and used by another client (`conflict`, naming them all in
  `holders`), or locked by
  another process (`conflict`, naming it from Ghidra's lock file). A source that only the caller
  holds writable is forked under its exclusive lock once nothing in it is unsaved
  (`unsaved_changes` otherwise). The source's revision is read before and after the copy; a
  change in between removes the copy and answers `conflict` naming the changed files.
- **Sidecar.** The fork's source and base revision are written to `<name>.fork.json` next to its
  `.gpr` (Ghidra ignores the file): `source` (`gpr`, `canonical`, `name`, `revision`, whether it
  was itself a fork), `baseRevision`, `created`, `by` (the client), `mode`, `method`, `cloned`,
  `bytes`, `depth`, and `parent`: the source's own sidecar when the source is a fork, so a fork of
  a fork keeps its whole lineage. `project` and `projects` show it as `fork`.

Measured on Windows 11 (build 26300) with a 1.49 GB analysed project (10 files, a 66.7 MB
executable with 243,855 functions), three runs:

| Fork | Time | Space used |
|---|---|---|
| Same ReFS volume (block clone) | 204-225 ms (249-312 ms for the whole request, opening the fork included) | 2.8-5.0 MB |
| To an NTFS volume (`mode: full`) | 8.5 s | 1.56 GB |

For comparison, a single 261 MB database file: 14 ms and 36 KB cloned on ReFS, 2.0 s and 262 MB
copied to NTFS.

### Shared writing: several clients write one program

`open_program` with `"writable": true, "share": true` opens a program in **shared mode** (or
joins it): every client that does so is one of its `writers` and may `rename`, `comment`,
`edit`, `analyze`, `save`, `discard_edits` and run changing scripts on it, at the same time as the
others. Owner mode (the default, one owner) and shared mode do not mix on one program: a
writable open without `share` of a shared program gets `conflict` with `suggest: "share"`; an
owner may turn its program shared by opening it again with `share`.

- **One change at a time.** Each change is its own short transaction, committed under the
  program's exclusive lock, so changes from different clients never interleave inside one
  transaction (Ghidra joins concurrent transactions on one program into one, which would let one
  client's rollback undo another's work). Readers share the lock between changes. A committed
  change is visible to every client at once: they share one program object.
- **Writes are serialized, and no corruption was seen in the tests listed (see
  [Tests](#tests)), but they are not collision-checked unless you ask.** **Last writer wins** per value (a name, a comment of a type at an address,
  ...) by default; `expect` is optional on each call, not required. To detect a
  lost update instead, pass `"expect"` (the value you read; `null`: none) on `rename`, `comment`
  or an `edit` operation of those kinds: if the value changed since, the change is refused with `conflict`,
  `reason: "changed"`, the `current` value, and the last editor (`lastEdit`, `holderInfo`).
- **`edit`** `{program?, ops}` applies the overlay operations (`rename`, `label`, `comment`,
  `signature`, `data_type`; `rename`, `label` and `comment` take an optional `expect`) to a
  writable program in one transaction, all or none, and journals them.
- **Author journal.** Every committed change of a writable program (owner or shared mode) is
  journalled: `seq` (commit order), `at`, `client` (id), the `name` and `harness` of the request
  that made it, `cmd`, `op`, `address`, `old`, `new`, and the change's details. `journal`
  `{program?, since: seq, author: client id, limit}` lists it; `info` and `status` show
  `journalSeq` and `unsavedEdits` (changes after the last save, `savedSeq`). It keeps the last
  200,000 entries per program.
- **`discard_edits`** `{program?, author}` reverts one client's unsaved renames, labels and
  comments, newest first, each only while the value is still what that client wrote; values
  someone changed since, and analysis or script changes, are reported in `skipped`.
- **Saving.** Any writer may `save` (the whole program, everyone's changes). A last writer that
  closes it with unsaved changes gets `unsaved_changes` (save, or `"discard": true`, which
  discards everyone's unsaved changes).
- **A writer that dies.** Its running request is cancelled; a change it had not committed is
  rolled back (its own transaction, nobody else's); every committed change stays. When it was the
  last writer and changes are unsaved, the program stays open in shared mode with no writers
  (`status`: `writers: []`, `orphanedMs`, `unsavedEdits`), and so does its project, until a
  client joins with `share` and saves or discards; only a daemon shutdown discards it (logged).

Tested: two writers and a third client (`shared`: visibility, the journal, `expect`,
`discard_edits`, a killed writer, a killed last writer, reopen); 4 clients x 2 threads making
3,200 renames and comments with 64 saves in 6.0 s on a small program, with no failed, lost or
duplicated edit, the journal complete and ordered, the program holding each value's last edit,
and the project reopening with all of it (`shared_stress`).

### Overlays: a private annotation view of a shared program

**The need.** One client wants to try a name, a comment, a label, a signature or a data type
while other clients keep reading the same program; nobody else must see it, nothing may be saved
unless the client decides to keep it, and a client that dies or fails must not leave anything
behind in the shared program. A fork per hypothesis is heavier than that needs.

**Why not a view of the shared program.** Ghidra has no per-client view of one `Program` object:
a change in a program object is a change for everyone holding it, and the session shares one
object per program among its readers. Contained scripts get isolation only by rolling everything
back at the end (other clients can see their changes while they run), so they cannot keep a
change for later requests.

**What was evaluated:**

| | (a) a private copy-on-write fork per overlay | (b) a private program object plus an operation log (chosen) |
|---|---|---|
| What | `fork_project` of the program's project, opened writable for the client behind the overlay name | A second program object over the same stored file (`DomainFile.getReadOnlyDomainObject`: Ghidra's "new domain object that is disassociated from its original domain file", changeable, never saved back), changed only through logged operations |
| Isolation | A separate project | A separate program object; its database reads the stored file and keeps changed buffers in its own temporary file |
| Never saved | Needs care: the fork is writable | By construction: a read-only domain object cannot be saved to its file |
| Cost, 243,855 functions (1.49 GB project) | 455 ms fork (402-537) + 301 ms open (288-366) + 468 ms first decompile; a project on disk to delete; a full copy (8.5 s, 1.56 GB) where the file system does not clone | **116 ms open (110-213), +54 MB heap**, 252 ms first decompile, then 9 ms decompiles and 1.2 ms per rename; nothing on disk |
| Cost, 174 functions | 102 ms fork + 30 ms open | 26 ms open, +3 MB heap |
| Promote | It is already a project | Replay the log into a fork |

(Windows 11, ReFS, JDK 25; medians of 3 rounds for the large program and 5 for the small one,
min-max in brackets; the shared program was already open and warm, as it is when other clients
use it.)

So an overlay is (b): **its own program object over the shared program's stored file**, and a
**log** of the operations applied to it, which `promote_overlay` replays into a working copy and a
`refresh` replays into a rebuilt overlay.

```json
{"cmd": "open_program", "path": "p1:/game.exe", "overlay": "agent-a"}
{"cmd": "apply_overlay", "program": "p1:/game.exe", "overlay": "agent-a", "ops": [
  {"op": "rename", "address": "rva:0x67bc40", "name": "PlayerTick"},
  {"op": "comment", "address": "rva:0x67bc40", "type": "plate", "text": "hypothesis: per-frame update"},
  {"op": "label", "address": "rva:0x1a2b30", "name": "g_playerList"},
  {"op": "signature", "address": "rva:0x67bc40", "signature": "void PlayerTick(void *self, float dt)"},
  {"op": "data_type", "address": "rva:0x1a2b30", "type": "void *[64]"}]}
{"cmd": "decompile", "program": "p1:/game.exe", "overlay": "agent-a", "address": "rva:0x67bc40"}
{"cmd": "promote_overlay", "program": "p1:/game.exe", "overlay": "agent-a", "fork": {"path": "C:/work/agent-a"}}
{"cmd": "drop_overlay", "program": "p1:/game.exe", "overlay": "agent-a"}
```

- **Scope.** An overlay belongs to one client and one program, by name (`overlay`: 1-64 letters,
  digits, `.`, `_`, `-`, `@`). Another client's overlay of the same name is a different one; no
  other client can use or see it. `open_program` with `overlay` opens the shared program
  read-only for the client (as without it) and creates or joins the overlay. The same client
  still reads the canonical program by leaving `overlay` out.
- **Reads** with `overlay`: `info` (`mode: "overlay"`), `functions`, `decompile` (the overlay's own
  pooled decompilers) and `script` (contained: rolled back, as on a shared program).
- **Changes** go through operations only, so that they can be replayed: `apply_overlay` with
  `ops` (`rename` {address, name, kind}, `label` {address, name}, `comment` {address, text,
  type}, `signature` {address, a C prototype}, `data_type` {address, type such as `int`,
  `char[16]` or `MyStruct *`}), and `rename` / `comment` with `overlay`. A call is atomic: one
  transaction, and the first failing operation rolls the whole call back (the error names its
  `index`; `rolledBack: true`); the overlay is unchanged and its version stays.
- **`overlayVersion`** is bumped by every successful call. Each overlay is described (in its
  answers, in `info` and under `overlays` in `status`) as `name`, `program`, `client`,
  `overlayVersion`, `ops`, `sha256` (the program's executable), `programRevision`,
  `projectRevision`, `gpr`, `stale`, `error`, `changed`, `openMs`, `ageMs`. `info` without
  `overlay` lists the client's overlays of the program; `overlays` lists all of the client's.
- **Never saved.** Nothing in an overlay reaches the stored program. `promote_overlay` replays its
  log into a writable copy of the program, in a project the client opened writable (`project`)
  or in a new fork of the overlay's project (`fork`: the `fork_project` fields), checks the
  target is the same build (SHA-256), and saves it unless `"save": false`. The overlay stays.
- **Lifetime.** `drop_overlay`, `close_program`, `close_project`, the client's disconnect or
  death, and the program closing for everyone drop it. A `refresh` of the project rebuilds it from
  its log over the new revision; if the program is another build then (another SHA-256) or an
  operation no longer applies, the overlay is marked with `error` and is unusable until dropped
  (its log comes back in the error's details).
- **Failures stay inside.** An overlay is a different program object: nothing done to it, and no
  failure in it, reaches the shared program or other overlays.

**Limits, and when a fork is the better tool.**

- An overlay costs a program object's memory (measured +54 MB for 243,855 functions, mostly
  caches that grow with use) and pays its own first decompile (about 250 ms); many overlays of
  a large program add up. For long, heavy work on one program, a fork costs disk instead of heap.
- Only the five operations above change an overlay. Bulk type imports, structure creation,
  analysis, version tracking or any script that must keep its changes need a working copy:
  `fork_project` (or `promote_overlay` into a fork, then work there).
- An overlay of a program in an older database format opens from the upgrade cache copy when the
  shared program came from it; otherwise it is upgraded in memory, as slowly as that program's
  first open (21-24 s for the large program above).
- Promotion replays operations by address; it does not merge with other changes in the target.

### Programs saved by an older Ghidra

Opened read-only, a program in an older database format is upgraded in memory on every open,
which for a large program takes many times longer than the open itself (a 66.7 MB executable with
243,855 functions saved by 12.1.4: 21-24 s on master instead of about 1 s). The **upgrade cache**
makes an upgraded copy once, in the background, and serves later opens from it:

1. Before opening, the session reads the program's stored database version and language version
   from its database (a few milliseconds, without opening the program). A current program opens
   as usual.
2. **First open.** An older program with no copy yet is upgraded in memory, exactly as without
   the cache, and the answer goes out at once with `"cachedUpgrade": false, "cacheBuild":
   "started"`. Its clients keep using that in-memory program.
3. **The build**, on one background thread: it waits for the key's build lock (another daemon may
   be building it), then for a slot in the **long** lane, which it gets only while no client's
   request waits for one (it never touches the quick lane); then it copies the project into
   `<upgradeCacheDir>/<key>/g<n>.tmp` (with the platform's copy, which block-clones on ReFS and
   other file systems that can), opens the program there writable, upgrades and saves it, checks
   that the source did not change meanwhile, renames the folder to `g<n>` and only then names it
   in `<key>/entry.json` (written atomically). Readers open only the generation `entry.json`
   names, so they never see a half-written copy.
4. **Later opens** find the copy and open the program read-only from it (`"cachedUpgrade":
   true`). The in-memory program is never switched under a client: once nobody uses it, the next
   open takes the copy, and the reaper closes it (it holds the in-memory upgrade's temporary
   database) instead of keeping it warm.
5. **While it builds**, other opens of the program join the in-memory one, or upgrade in memory
   again if it was closed meanwhile; only one build per key and program runs. An
   `open_program` with `"wait": true` instead starts or joins the build and waits for it (holding
   no program lock), then opens from the copy.
6. **Failures.** A build that fails or is cancelled (`cancel` with `"cacheBuild"`, the daemon's
   shutdown, a source that changed during the build) deletes its temporary folder and is logged;
   the next open starts a new one. A daemon killed mid-build leaves its `.tmp` folder, which the
   next start (or the next build of that key) removes. On shutdown a running build is cancelled
   and given 3 s to clean up; one that has not stopped by then is left to the exit and cleaned up
   by the next start.

A further program of the same source is upgraded in a fresh copy of the current generation (one
more block clone), published as the next generation; older generations are removed once no
daemon reads from them (shared OS locks on `<key>.use` and `<key>/g<n>.use`).

`open_program` and `info` report `"cachedUpgrade"`, `"upgradeCache"` (`key`, `generation`, `dir`,
`reason`, `openMs`) when served from the copy, and `"cacheBuild"`: `none` (current format, or the
cache is off), `started` (this open started it), `building`, `ready` or `failed`, with
`"cacheBuildInfo"` (the build's `id`, `phase`, progress, `error`, per-phase `phaseMs`). `status`
lists every build under `upgradeCache.builds` (`state`, `phase`: waiting for the build lock,
waiting for a long slot, copy, upgrade, save, publish; `message`, `progress`, `maximum`, `ms`,
`error`, `cancelled`) and the program's `cacheBuild` under `programs`.

The key is the source's identity: the canonical path of its `.gpr`, this Ghidra's version, build
date and program database version, and every file of the `.gpr` and `.rep` with its size and
modification time, plus the SHA-256 of every file up to 1 MiB (the `.gpr`, property and index
files). Ghidra writes its large database files whole, as new versions, never in place, so their
size and time identify them; hashing them on every open would cost more than the open. Any change
makes a new key, and the copies of older keys of the same source are removed once no daemon uses
them (a key is built under an exclusive OS lock on `<key>.lock`, so several daemons can share the
directory). The source is only ever read.

Turn it off with `"upgradeCache": false`.

## Protocol (version 2)

> Protocol 3 (hydra.4) is served beside protocol 2 on the same port; a client that asks for nothing newer gets
> protocol 2 exactly as described below. What a protocol 3 client may ask for, and every change a protocol 2
> client can see, are in [PROTOCOL-3.md](PROTOCOL-3.md) (section 5.1) and in the release notes
> (`docs/release-notes-12.3-hydra.4.md`). The design is not complete in this tree: a part that is not part of the
> release is not described in this README.

One JSON object per line, UTF-8, `\n`-terminated, at most 64 MiB per line.

Request:

```json
{"id": 7, "cmd": "decompile", "program": "p1:/game.exe", "address": "rva:0x5d53a0", "wait": 10000}
```

- `id`: any JSON value; the response echoes it. Unique among this client's unanswered requests.
- `cmd`: the command.
- `wait`: milliseconds the request may wait for a scheduler slot or a lock before it fails with
  `busy` (default 10000). The one exception is an `import` waiting in the import queue, which
  waits without limit unless it passes a numeric `wait` ("The import queue").
- `parallel`: `true` runs the request at once on its own thread. Without it, one client's
  requests run in the order sent (other clients always run in parallel). Use it when one
  connection carries several independent callers, as an MCP server's does.
- `client`, `harness`: optional labels of this request alone. They replace the connection's
  name (from `hello`) wherever people are told who does what: the holder in `busy` and
  `conflict` answers, `status`, the import queue, and the scope of `cancel`. See "Who is
  asking". Strings of at most 128 characters.

Response:

```json
{"id": 7, "ok": true, "result": {...}, "ms": 12}
{"id": 7, "ok": false, "error": {"code": "busy", "message": "...", "details": {...}}, "ms": 500}
```

A response may also carry `stale` and `refreshed` (see "Revisions and `refresh`").

Events carry no `ok`. On stdio the first line is `ready` (or `fatal`, and the process exits with
code 2). Long commands send throttled `progress` events with the request's `id`:

```json
{"event": "ready", "protocol": 2, "ghidra": "12.3", "pid": 1234, "launch": {...}, "startupMs": 700}
{"event": "progress", "id": 9, "message": "Analyzing...", "progress": 120, "maximum": 400}
```

### Projects, programs, keys

- `open_project` returns the project's **id** (`p1`, `p2`, ...), stable while it is open, and makes
  it the client's **active project**.
- A program's **key** is `<project id>:<project path>`, for example `p1:/libs/version.dll`. Keys
  are unique across projects.
- `open_program` makes the program the client's **active program** (and its project the active
  project).
- `project` (field) selects a project by id or by path; `program` (field) selects a program by key,
  or by path or unique name in the selected project. Without them a command acts on the active
  project or program.

### Commands

| `cmd` | Fields | Does |
|---|---|---|
| `hello` | `client`, `harness`, `clientVersion`, `token` (socket) | Names the client. On a socket it must be the first request, with the endpoint's `token`. Answers the session's identity: `protocol`, `minClient`, `hydraVersion`, `ghidraVersion`, `installId`, `startedAt`, `pid` (see "Pinning and upgrading"), then what `status` lists. |
| `ping` | | `{"pong": true}` |
| `status` | | Session identity (as `hello`), launch info, memory, projects, programs (mode, owner and `ownerLabel`, users, what holds each lock, idle time), clients (`name`, `harness`, `clientVersion`, and their unanswered `requests`: `id`, `cmd`, `artifact`, `ms`, `message`, `progress`, `maximum`, and `client`, `harness`, `labelled`, what it waits for (`waiting`) and its `queue` position), overlays, scheduler lanes (running and waiting requests, by label), the import queue (`imports`), upgrade cache builds, and `youAre`, the label this request carried. |
| `projects` | | Open projects, which ones this client joined, its active project. |
| `open_project` | `path`, `writable`=false, `discard`=false | Joins the project, opening it if needed. `path` is a `.gpr`, its folder, a `.rep`, or a parent folder with exactly one project at most two levels below. A writable open of a read-only view reopens it writable in place, also while other clients use it (same id and keys; refused with `conflict` only when another process holds the project lock); a second writable open joins; a read-only request on a writable project joins it. |
| `fork_project` | `project` (id or path), `path`, `name`?, `writable`=true, `mode`=auto\|copy-on-write\|full, `maxCopyMb`? | Copies the project into a working copy of this client's, opened and joined; the source and its read-only views are untouched. See "Working copies". |
| `close_project` | `project`?, `discard`=false | Leaves the project (closes this client's programs there). A writable project closes when its last user leaves; a read-only one after `keepWarm`. |
| `project` | `project`? | The project: id, name, paths, writable, files, users, programs, `revision`, `diskRevision`, `stale`, `generation`, and `fork` (its sidecar's summary) when it is a fork. |
| `refresh` / `reopen` | `project`?, `force`=false | Reopens a read-only view on what is saved now, for all its clients at once. See "Revisions and `refresh`". |
| `list` | `project`?, `folder`="/", `recursive`=true, `programsOnly`=false, `metadata`=true, `sha256`, `offset`, `limit`=1000 | Folders and files, with `key`, `sha256`, `language`, `format`, `executable` and `open` (who uses it) for programs; `sha256` finds a program by its hash. Paged, with `truncated`. |
| `open_program` / `switch` | `path` (path, unique name or key), `project`?, `writable`=false, `share`=false, `overlay`?, `checkout`=false, `upgrade`=false, `wait`: `true` | Opens the program, or joins it if it is open (also a warm one nobody uses), and makes it active. Writable needs a writable project; a versioned file needs `checkout`. `"wait": true` on a read-only open of an older-format program waits for its upgrade cache copy instead of upgrading in memory (slot and lock waits keep the default). |
| `programs` | | This client's programs (all projects) and its active ones. |
| `open_program` + `share` | `path`, `writable`: true, `share`: true | Opens (or joins) the program in shared mode: several writers. See "Shared writing". |
| `edit` | `program`?, `ops` [...] | Operations (`rename`, `label`, `comment`, `signature`, `data_type`; the first three with an optional `expect`) on a program this client may write, all or none, journalled. |
| `journal` | `program`?, `since`, `author`, `limit` | Who changed what in a writable program, in commit order. |
| `discard_edits` | `program`?, `author` | Reverts that client's unsaved renames, labels and comments (a label it created is deleted), newest first; what others changed since is kept and listed in `skipped`. |
| `open_program` + `overlay` | `path`, `overlay` | Opens the program read-only for this client and creates or joins its private overlay. See "Overlays". |
| `apply_overlay` | `program`?, `overlay`, `ops` [...] | Applies operations (`rename`, `label`, `comment`, `signature`, `data_type`) to the overlay, all or none, and logs them. |
| `drop_overlay` | `program`?, `overlay` | Drops the overlay. |
| `promote_overlay` | `program`?, `overlay`, `project` or `fork` {`path`, `mode`, ...}, `path`?, `save`=true | Replays the overlay's log into a writable copy of the program (a project this client opened writable, or a new fork) and saves it. |
| `overlays` | | This client's overlays. |
| `info` | `program`?, `overlay`? | Key, language, compiler, image base, format, executable path, SHA-256, MD5, functions, analysed, changed, mode, owner, users, `revision`, `projectRevision`, `generation`, `overlays` (this client's). With `overlay`: the program as the overlay shows it. |
| `close_program` | `program`?, `discard`=false | Drops this client's use. The owner of a changed program must `save` first or pass `discard`. |
| `functions` | `program`?, `contains`, `regex`, `offset`, `limit`=200 (max 10000), `overlay`? | Functions by name filter, paged. |
| `decompile` | `program`?, `address` or `name`, `timeout`=60 s, `maxChars`=200000, `overlay`? | C text and signature. Decompilers are pooled per program (and per overlay), so warm calls skip the start-up cost. |
| `rename` | `program`?, `address`, `name`, `kind`=auto\|function\|label, `expect`?, `overlay`? | Renames the function at the address, or creates or renames the primary label: data labels and global names. Owner or shared writers only; with `overlay`, in the client's overlay. Answers `old`, `created` and the journal `seq`. |
| `comment` | `program`?, `address`, `text` (null clears), `type`=eol\|pre\|post\|plate\|repeatable, `expect`?, `overlay`? | Owner or shared writers only; with `overlay`, in the client's overlay. Answers `old` and the journal `seq`. |
| `analyze` | `program`?, `options` {name: value}, `ranges` [[start, end], ...], `timeout` s | Sets analysis options, then runs auto-analysis on everything (or what the ranges trigger) the way `analyzeHeadless` does, and marks the program analysed. Owner or shared writers only; journalled. |
| `save` | `program`?, `comment` | Saves the program (everyone's changes on a shared one). Owner or shared writers only. Answers `revision`, `projectRevision` and `savedSeq`. |
| `import` | `file`, `project`?, `folder`="/", `name`, `language`, `compiler`, `analyze`=false, `duplicate`=false, `timeout` | Imports into a writable project with `ProgramLoader` (any format it accepts), saves it, opens it writable for this client, and optionally analyses and saves it. A file whose SHA-256 is already in the project returns `{"imported": false, "existing": [...]}` unless `duplicate`; the same file sent twice at once into one project is imported once (the second waits for the first and answers `existing`, with `sameFileImport`). Up to `maxImports` imports run at once, in any projects; more queue in arrival order (see "Parallel imports"): the answer carries `queue` (`waitedMs`, `positionAtEntry`, `behind`, `runningAtStart`), and a request that waits sends `progress` events "waiting behind ..." with its `queue` position and estimate. `wait` limits the time in the queue only when it is a number; by default a queued import waits until it runs or is cancelled. |
| `script` | `script` (name on the script path, or a file path; a Java file must be in a script folder, see "Scripts"), `args` [...], `program`? (null: none), `project`?, `address`, `exclusive`=false, `save`=false, `timeout` s, `maxChars`, `artifact` (a path the script writes; echoed in `status` and the result) | Runs a GhidraScript and returns its `println` output (`output`, `truncated`), its `mode` (`owner` or `contained`), `changed` (whether the script changed the program; false when contained) and `unsaved` (whether the program has unsaved changes, anyone's). See "Scripts". |
| `cancel` | `target` (an id of this client's request), or `all`: true, or `cacheBuild` (a build id, cache key, program key or path, or `all`) | Cancels it (or all of this client's requests), running or still queued (a queued import leaves the import queue; the running ones are untouched). With `client`/`harness` on the `cancel`, `all` reaches only the requests of that label, and `target` refuses another label's request. `cacheBuild` cancels background upgrade cache builds, which belong to no client. |
| `shutdown` | `force`=false | Stops the session; unsaved changes are discarded. From a socket client it is refused while other clients are connected, unless `force`. |

Addresses are `0x140001000`, `va:0x140001000`, `rva:0x1000` (from the image base) or
`space:offset`. Results print addresses as `0x...` in the default space.

### Error codes

`bad_request`, `unknown_command`, `unauthorized`, `no_project`, `no_program`, `not_found`,
`read_only`, `not_owner`, `busy` (with what holds the slot or lock and for how long), `conflict`,
`unsaved_changes`, `cancelled` (also on `timeout`), `failed` (Ghidra's message, plus a short
`trace`). What `not_owner`, `conflict` and `busy` mean between clients is in "Who can do what at
the same time".

**Who holds it, and what to do.** `busy`, `conflict`, `not_owner` and `read_only` answers carry,
in `error.details`:

| Field | Meaning |
|---|---|
| `holder` | A one-line label of the holder (`"client 3 (agent-b, claude-code) script Export.java"`). |
| `holderInfo` | The holder: `client` (id), `name`, `harness`, `label`, `command` (what it is doing: `open_program writable`, `script X`, `analyze`, `refresh`, ...) and `heldMs`. For a project locked by another process: `label: "another process"`, `user`, `host`, `since` and `os` from Ghidra's lock file, `lockFile`, and `live` (whether that process still holds it). |
| `holders` | Only in a `conflict` from `fork_project` whose source is open writable in this daemon and used by other clients: each of them as a `holderInfo`. (A refused `open_project` names the other process in `holderInfo`.) |
| `project`, `gpr`, `name`, `writable`, `revision` | The project concerned (its revision: see "Revisions and `refresh`"). |
| `program`, `path`, `sha256` | The program concerned: its key, its project path and its executable's SHA-256. |
| `suggest` | What to do: `retry` (a lock that will be released: retry or raise `wait`), `fork_project` (the project or program has another writer, or is a shared read-only view: write your own working copy), `open_read_only` (another process holds the project writable), `open_program writable`, `share` (the program is shared: join its writers), `reread` (`expect` failed: the value changed since you read it). `not_owner` adds `alternatives` (`overlay`, `fork_project`) and an `overlaySuggestion` request. |
| `suggestion` | With `suggest: fork_project`: a ready request, `{"cmd": "fork_project", "project": "p1", "path": "<a folder next to the project>", "writable": true}`. The path is only a proposal. |

## Several clients

- **Projects are shared.** Clients that open the same project (by any path to it) use one
  instance. Each program and project has its own lock. They share the daemon's lane slots and
  import gate, so enough long work anywhere can delay a save or fork elsewhere.
- **Programs are shared.** Two clients that open the same program use one instance and decompile
  it in parallel with separate pooled decompilers.
- **Each program has a fair read/write lock.** Queries and contained scripts share it. Edits,
  analysis, saves, owner scripts and mode changes hold it alone. A request that cannot get it
  within `wait` fails with `busy`, naming the holder (client, harness, command, how long).
- **One owner per program, or shared writers.** By default only the client that opened a
  program writable may `rename`, `comment`, `edit`, `analyze`, `save` or run a changing script;
  others get `not_owner` (with `alternatives`: an overlay, or a fork); they may still read it and
  then see the owner's unsaved changes. Opened with
  `"share": true`, a program has several writers at once ("Shared writing").
- **Two lanes.** Requests take a slot in one of two lanes before any lock: **quick**
  (decompile, functions, list, open, rename; one slot per CPU) and **long** (analyze, import,
  script, save; `max(8, CPUs)` slots by default; a quarter of the CPUs, at least two, up to 12.3-hydra.3). Native commands stay in the quick lane while imports and
  analyses run in the long lane. Scripts run in the long lane, so a client that asks its
  questions through scripts shares it, and a full long lane delays those questions (measured up
  to about 8 s). Readers of the program being analysed wait for its lock. When a lane is full,
  waiting requests are admitted round-robin by connection, and while another connection waits a per-connection cap limits how
  many slots one connection runs (`maxRunningPerKey`; up to 12.3-hydra.3 there was no cap). The daemon's own background work (upgrade cache builds) takes a long slot
  only while no client waits for one. `status` shows each lane's use and queue.
- **Cancellation is per client**, and per label when the request carries one (below). `cancel`
  stops requests waiting for a slot or for a program lock, and cooperative scripts (before
  12.3-hydra.4 a lock wait stayed until its `wait` ran out).
- **Leaving.** When a client disconnects or its process dies (the OS resets its socket), its
  requests are cancelled and its uncommitted changes are rolled back (and logged) when its
  running request ends, and its programs go back to read-only for the others. A request-bound
  lock wait (a program, a project, an overlay's request lock site) ends on cancel; the overlay
  lifecycle waits (open, rebuild, drop, promote of an overlay) are untimed and are not ended by
  `cancel`, a `timeout` or the release (Limits, L2). A request that is still running `cleanupGraceS` (15 s) after the disconnect is
  interrupted, and `abandonWaitS` (5 s) later the client is released even if it ignores that: the
  locks it holds are flagged abandoned and a request for such a program answers `busy` at once.
  Only a script that does not poll for cancellation runs to its own end (Java cannot stop it).
  Another client that asks for the program meanwhile waits within its `wait`.
- **Opening a project writable while other clients use its read-only view reopens it writable
  in place**: same id and keys, their programs reopened from the writable project (read-only for
  them), their overlays rebuilt; they are told once with `refreshed`. A second writable open
  joins. A read-only client in a writable project opens programs read-only.

## Who can do what at the same time

The rules above, as a table. "Same program" means the same file in the same project; a read-only
view and a writable project are described in "Read-only view, writable project".

| Situation | Result | Why |
|---|---|---|
| Several readers of one program | in parallel | No project lock; they share one warm program and each decompile takes its own pooled decompiler. Queries hold the program's shared lock. |
| Several read-only views of one project (also other processes) | in parallel | A read-only view takes no project lock and writes nothing. |
| Writers in **different projects** | in parallel | Each project and program has its own lock. They share the daemon's lane slots and import gate, so enough long work anywhere can delay a save or fork elsewhere. |
| Two writers of the **same program** | owner mode (default): one wins, the other gets `not_owner` with `alternatives: ["overlay", "fork_project"]`; shared mode (`"share": true`): **both write** | Owner mode: one owner, the client that opened it writable; others may read it and see its unsaved changes, or annotate their own overlay. Shared mode: every writer's change is committed in its own transaction, one at a time, under the program's exclusive lock, visible to all at once, journalled with its author; last writer wins per value, `expect` turns a lost update into `conflict` ("Shared writing"). Owner and shared mode do not mix on one program. |
| Two writers on **different programs of one writable project** | in parallel | A second client that opens the project writable joins the daemon's one writable instance (one project lock). Each program has its own lock and owner (or shared writers), so renames, comments, analysis and saves of two programs run at the same time (tested: 2 writers x 600 edits, 14 saves and an analysis each, then the project reopens with all of them). They share the project's lifetime: it closes when its last user leaves, and a script with project access can reach every program in it. |
| A second **process** (another Ghidra process, `analyzeHeadless`, another daemon) opens a project this daemon holds writable, or the reverse | `conflict` | The project lock is held by one process; the error names the lock file. |
| `open_project` writable while another client of this daemon uses its read-only view | reopened writable **in place** | The daemon takes the project lock, replaces the view under the project's exclusive lock (requests running on it finish first) and reopens its clients' programs from the writable project, same keys; their overlays are rebuilt; they see `refreshed` once. Refused (`conflict`, `suggest: "open_read_only"`) only when another process holds the project lock. Measured with a reader using a 243,855-function program: 130-152 ms, and the reader's next decompile 246-259 ms (a new decompiler on the reopened program). To keep the master unchanged, `fork_project` it instead. |
| Read-only view of a project another process has open and saves | works, flagged `stale` | It shows the project as it was when the view opened; its clients are told with `stale` on their next answers, and `refresh` reopens the view for all of them at once, without anyone leaving ("Revisions and `refresh`"). |
| Concurrent `import`s of **different files** | in parallel, up to `maxImports` | Into different projects or into one: each load is handed its own project, and nothing on the load path reads the process-wide "active project". Beyond `maxImports` they queue first-come, first-served, visible in `status.imports` (running, position, estimated wait), cancellable without touching the running ones: see "Parallel imports". |
| Concurrent `import`s of the **same file into one project** | once | The second waits for the first and answers `imported: false` with `existing` (unless `duplicate`). |
| An `import` while other clients read the project | in parallel | Readers were not slowed beyond noise in the measurement below. Ghidra holds the project's file-system lock while it writes a new program into the project, so a `list` or `open_program` of that project may wait for that write (a few seconds for a large program); `decompile` and other queries of open programs do not. |

What the codes mean when two clients meet:

- **`not_owner`**: the program is open writable by another client of this daemon, and you asked
  for something only its owner may do (`rename`, `comment`, `edit`, `analyze`, `save`, a changing
  script, or a writable `open_program`). `details.owner` is the owner's client id (the
  `clients` list of `status` names it and its harness). Read it, annotate your own overlay
  (`overlaySuggestion`), wait for the owner to save and close it, or `fork_project` the project
  and work in the copy (`suggest`, `suggestion`, `alternatives`). On a shared program a client
  that is not one of its writers gets `not_owner` with `suggest: "share"`: join them.
- **`conflict`**: the project, not a program, cannot be given to you as asked: its lock belongs to
  another process, a shared program was asked for in owner mode (`suggest: "share"`), a value
  changed since you read it (`expect`, `reason: "changed"`, naming the last editor), the
  session is shutting down, a program needs a database upgrade you did not allow (`"upgrade":
  true`), a name is ambiguous, or a `fork_project` cannot start (the source is being written,
  the destination exists, the copy is larger than allowed: `details.reason`). Nothing is
  waiting: retrying will not help until the situation changes.
- **`busy`**: a slot or a lock did not come free within `wait` (default 10 s). `details` names the
  lane or the program, what wanted it, and the holder (client, harness, command) and for how
  long. Retry, or pass a longer `wait`; nothing was queued past the deadline.

All three carry `holderInfo` and `suggest` in `details` (see "Error codes"): who holds it, and
whether the answer is to retry, to fork, or to open read-only.

### Parallel imports

Up to **`maxImports`** imports load and save at once (default: one per four CPUs, between 1 and
4), into different projects or into one; the others queue (below). Each runs in its own request
thread: its own `ProgramLoader`, handed its own project, its own `MessageLog` and monitor, then
its own save. The open and the analysis of `analyze: true` follow outside the gate, in the
import's long slot, so analyses of imported programs run side by side as they always did,
bounded by `maxLong`, and the next import can load meanwhile.

**Why parallel loads are possible.** Imports used to run one at a time because Ghidra's loaders were thought to
read project state through the process-wide "active project" (`AppInfo`). Reading the load path
(Ghidra master, 12.3 DEV) shows what actually reads global state:

| Global | Read on the load path? | What it means for parallel imports |
|---|---|---|
| `AppInfo.getActiveProject()` | Only by `LibrarySearchPathManager` (once, when the class loads, and when someone changes the paths). The loader options' editors (`Option.getState()`, the browse buttons of `DomainFolderOption`/`DomainFileOption`) read it, but only in the import dialogs of Ghidra's interactive tool, which a headless process does not have. | Nothing. The session no longer sets the active project for an import. |
| `LibrarySearchPathManager` path set | A static set, loaded once from whatever project was active first, read under `synchronized` by loaders that search for libraries. | Every import in the process reads the same set, whatever its project, exactly as it did when imports were serialized (`examples/ImportIsolationProbe.java`, `daemon_tests.py import_isolation`: a path added while project A is active is visible while B is active and is not in B's saved state). The session never changes it; a script that calls `LibrarySearchPathManager.setLibraryPaths` changes it for every later import. |
| Language and compiler specs | `DefaultLanguageService`: loading a language is `synchronized` per language. | Two imports of one new language wait for its one load. |
| Project data | Every `GhidraFolder` change takes the project's file-system lock (`synchronized (fileSystem)`); `createFile` writes the new program's database under it; the default (indexed) file system ignores a second `createFolder` of an existing name; `Loaded.save` retries with `name.0`, `name.1`, ... on `DuplicateFileException`. | Two imports into one project serialize only while each writes its program into the project; two files with the same name both land (`x`, `x.0`); two imports into the same new folder both land in it. |

Measured: four PE files at once (`mshtml.dll` 22.9 MB, `edgehtml.dll` 24.8 MB,
`Windows.UI.Xaml.dll` 17.1 MB, `ntoskrnl.exe` 12.5 MB from Windows 11; a script calling
`ProgramLoader` directly, no active project set; 24 CPUs, Dev Drive) took **54 s** against **141-158
s** one after the other: each load took as long alone as next to the others (40-55 s for the
DLLs, 8 s for the kernel), so nothing on the load path serializes them. Peak heap above the
baseline was **2.9 GB** at once against **1.5-1.8 GB** one at a time. In two rounds each way the
programs were identical (functions, defined data, symbols, memory blocks). Through the daemon
(`daemon_tests.py import_speed`): see "Performance".

**Why not a worker process.** An import in a separate JVM that imports into a scratch project
for the daemon to adopt was the alternative. It is not needed: the in-process loads measured
above do not share state that changes their result, and a worker would pay a JVM and Ghidra
start (seconds), a second copy of the language and class data, and a copy of the finished
database for every import.

**The same file twice.** Two imports of the same file (by SHA-256) into the same project at once
import it once: the second waits for the first to save (its `progress` says "waiting for client
2 (agent-a, ...)'s import of the same file"), then finds the result and answers `imported:
false`, `existing: [path]` and `sameFileImport` (`who`, `file`, `waitedMs`). If the first fails
or is cancelled, the second imports the file itself. `duplicate: true` skips the check and the
wait. The wait is per project: an import into another project does not wait for it.

**Readers.** Clients that read or decompile in a project while imports run into it are not
slowed beyond noise (`daemon_tests.py import_readers`, numbers in "Performance"). The one wait
is Ghidra's: listing or opening files of that project waits while an import writes its new
program into the project (the project's file-system lock, above).

**Failure.** A cancelled import (`cancel`, its client disconnecting or dying, the daemon
stopping) stops its load at the loader's next cancellation check, releases its program (and its
temporary database files) and leaves nothing in the project; the other imports go on. A cancel
that arrives once the load is done, while the program is being written into the project, is too
late: that write is not cancellable, and the import completes (`cancel` still answers
`cancelled: true`, meaning the request was told). A daemon
killed mid-import leaves no partial program: the program reaches the project only in the final
`createFile`, and the next daemon opens the project and imports the file again
(`daemon_tests.py import_kill`). A daemon killed during that `createFile` itself, while the
program's database is being written into the project, leaves an item without a file type, which
Ghidra removes when the folder is next listed (the third fix in "Changes outside this module"):
the program is then absent, never listed half-written, and the file imports again
(`daemon_tests.py import_write_kill`, killed at the first sight of the new database and at 30%
and 70% of the write). An empty data folder of the removed item may stay on disk; it is never
listed.

### The import queue

When `maxImports` imports run, the next ones wait, and the wait is visible and under control:

- Imports queue **first-come, first-served** at an `ImportGate`, **before** they take a
  scheduler slot, so queued imports do not occupy the long slots that analysis and scripts need.
- `status.imports`: `maxImports`, `running` (each: who, client id, project, file, bytes,
  running time), `holder` (the oldest running one, or null), `queue` (the same, plus `position`
  and `estimatedWaitMs`) and `history` (`count`, `meanMs`, `msPerMb` of the last 12 finished
  imports, and `peakRunning`, the most that ran at once). `status.clients[].requests[]` marks a
  queued import `"waiting": "import queue"` with its `queue` details, and an import waiting for
  the same file `"waiting": "same file import"`.
- A queued `import` sends `progress` events (at most one a second): `"message": "waiting behind
  client 2 (agent-a, claude-code) import of big.exe and 1 other import (position 1 in the import
  queue, about 40 s)"`, with `"queue": {"position", "ahead", "holder", "running", "maxImports",
  "estimatedWaitMs"}`. The final answer repeats what the wait was in `queue`: `waitedMs`,
  `positionAtEntry`, `behind`, and `runningAtStart` (how many ran, this one included, when it
  started).
- The **estimate** places each running import's remaining time, then each import ahead in the
  queue on the place that frees first, each taken as the history's rate (ms per byte of the last
  12 completed imports) times the file's size, never below the shortest import seen; the wait is
  when the next place frees after them. `null` until one import has finished in this daemon. It
  is a guide: format, loaders and options change an import's time, and so do the disk, the other
  imports and the other work on the machine. Measured in `daemon_tests.py import_queue` (with
  `maxImports` 1; random 128 MB raw binaries, Windows 11, Dev Drive): an import took 8.8-17 s;
  estimates made while queued were rough: one measured pair was 7.0 s estimated against 17.5 s
  waited, because the import ahead ran slower than the history's rate.
- **Cancelling a queued import** (`cancel` by id, `cancel all`, a disconnect) takes it out of the
  queue at once and answers `cancelled`; the running imports and the others queued are
  untouched. Cancelling a running import frees its place and the next one starts.
- An import waits in the import queue: without limit unless the request passes a numeric `wait`,
  in which case it fails with `busy` (details: the same queue information) after that long; the
  same `wait` also limits a wait for the same file. At the front it still needs a long slot:
  with a numeric `wait` it fails `busy` when that `wait` runs out; without a numeric `wait` it
  waits for the slot without limit (V2; up to 12.3-hydra.3 it failed `busy` after 10 s).
- Duplicates: the SHA-256 check runs when the import gets its turn, so two queued requests for
  the same file import it once and the second answers `imported: false`.

### Who is asking

A connection has one identity from `hello` (`client`, `harness`), but an MCP server serves several
agents over one connection. Any request may carry its own `client` and/or `harness`; each present
field replaces the connection's value for that request. With the label:

- `busy` and `conflict` answers name the **requester's label** as the holder (`details.holder`:
  `client 3 (agent-a, claude-code) script TestSleep.java`; `holderInfo` carries the same `name`,
  `harness` and `label`), as do `status` (`programs[].busy`,
  `ownerLabel` of a writable program, the scheduler's `running` and `waiting`, the import queue)
  and the daemon's log.
- `status.clients[].requests[]` lists each unanswered request with its `cmd`, age, `client`,
  `harness` and `labelled`; `status.youAre` echoes the label a `status` call carried.
- `cancel` with a label: `all` cancels only that label's requests (a request counts as that
  label's when it carried the same `client` and `harness`); `target` refuses another label's
  request (`"cancelled": false`). A `cancel` with no label keeps its meaning: all of the
  connection's requests.
- It changes **no ownership**: a program is still owned by the connection that opened it
  writable, so every label of that connection may use it as its owner; only the owner's *name*
  in messages is the label that opened it. Labels are for telling callers apart and for scoping
  cancellation, not an access control: anyone with the token can send any label.

`ghidra_session.py`: `s.call("decompile", client="agent-a", harness="claude-code", ...)` for one
request, or `a = s.labelled(client="agent-a", harness="claude-code")`, a view whose `call`,
`send`, `cancel(target)` and `cancel_all()` all carry the labels (and are `parallel` by default).

## Scripts

`script` runs a GhidraScript as headless Ghidra does: `currentProgram`,
`currentAddress`, `state.getProject()`, `getScriptArgs()`, `println`, `monitor`, and
`isRunningHeadless()` true. `HeadlessScript` subclasses also get `storeHeadlessValue` and
`getStoredHeadlessValue`. The session binds them to `HeadlessAnalyzer.getInstance()` through
Ghidra's package-private setter, reflectively, so no Ghidra class is changed.

- On a program **this client may write** (its owner, or one of its shared writers), the script
  runs exclusively and its changes stay in the program, unsaved unless `"save": true`; the
  journal records that it ran (`op: "script"`), not each change it made.
- Otherwise the script is **contained**: it runs inside an outer transaction that is always
  rolled back, so its changes are never saved; while it runs, other clients can see them.
  Contained scripts share the program lock and run in parallel, unless `"exclusive": true`. A script that must run
  outside every transaction, such as version tracking, which ends the script's transaction to
  take its own locks, must run as owner.
- With `"program": null`, or with no program open, it runs with only the active project (or
  none).

**Where scripts are found.** `script` takes a name, looked up in the script folders (Ghidra's own
and every `scriptPath` entry of `config.json` or `-scriptPath`), or a file path. A Java script is
compiled from its folder's source bundle, so its folder must be one of those script folders,
whichever way it is named: a `.java` file elsewhere fails with `script did not load: ... Failed
to find source bundle containing script`. Put your scripts' folder on `scriptPath` (the daemon
reads it at start: `stop`, then start it again).

A script is Java with the session's rights, so this is not a sandbox. Containment rolls the
script's changes back; it does not hide them from other clients while the script runs, and it
does not protect the machine.

`examples/HeadlessApiProbe.java` is a script that exercises the headless Ghidra API for what
interactive tools usually do: C headers parsed into a `.gdt` and applied, enum, union, typedef and
function-definition types, typed data with a global label, a global rename, a bookmark, auto
create structure from usage, and version tracking from another program in the project.

### Exports: a script that writes a large file

A bulk export (every function, string or reference of a program as JSONL, say) is a `script`
that writes its own file. This is the contract an integrator can rely on; every line of it is
exercised by `examples/contract_tests.py` with `examples/scripts/ExportJsonl.java` (600,000 lines,
about 55 MB, in the default run).

- **Where it writes.** Anywhere the daemon's user can write. The path is the script's own choice
  (usually an argument in `args`), not the project's: the session neither opens nor limits the
  file. Pass the same path as `"artifact"` in the request: it is echoed in the result and shown
  in `status`.
- **Not capped.** `maxChars` (default 200,000; at most 16,000,000) and the result's `truncated`
  apply only to the text the script `println`s, which is returned in `output`. They do not touch
  the file. (The printed text is held in memory for the result, so print a summary, not the
  data.)
- **Progress.** `monitor.initialize(total)`, `monitor.setProgress(n)` and `monitor.setMessage(...)`
  send `progress` events with the request's `id`, at most one per second, whatever the call rate.
  Send the request with `"parallel": true` (or from its own connection) so that `cancel` and
  `status` can be sent while it runs.
- **Seeing the job.** `status` lists, per client, `requests`: for every request not yet
  answered, its `id`, `cmd`, `artifact` (for a script, as declared), `ms` since it arrived,
  and the latest `message`, `progress` and `maximum` of its monitor; and `scheduler.long.running`
  shows its slot. When it ends, it leaves the list.
- **Cancel, timeout, shutdown.** `cancel {"target": <id>}` and `timeout` cancel the script's
  `monitor`: a script that calls `monitor.checkCancelled()` between batches stops promptly and the
  request answers `cancelled`. `stop` of the daemon, and a client that disconnects, cancel it the
  same way. What the script had already written stays on disk; the session deletes nothing it did
  not create. A script that ignores its monitor is not stopped (it runs inside the daemon's JVM),
  and a killed daemon (`kill`, a crash) cannot flush anything the script had buffered.
- **Write so that a partial file is inspectable.** The sample writes whole batches of lines to
  `<path>.part`, flushes after each, and renames to `<path>` only when it finishes. A cancelled or
  stopped export therefore leaves `<path>.part`, valid JSONL up to its last complete line, and no
  final file; a reader that finds `<path>` knows the export completed. Resuming is the script's
  job: the sample takes its start from its arguments, and a caller can read the count of lines
  from the `.part` file.

```python
rid = s.send("script", script="ExportJsonl.java", program=None, parallel=True, maxChars=1000,
             args=[out, 500000], artifact=out)         # runs on the long lane
...                                                    # progress events; s.call("status")
result = s.wait(rid)                                   # result["artifact"] == out
```

## How a client (for example an MCP server) should use it

1. **Connect.** From Python, `ghidra_session.connect(client=<your tool>, harness=<the agent
   harness>)`. It joins the user's daemon or starts it. From another language, run
   `python ghidra_session.py ensure` once, then read `<state>/default.json` and connect to its
   port. Keep one connection per process and send `"parallel": true` for independent calls.
2. **Adopt an analysed project, no import.** `open_project` with the `.gpr` or its folder (a
   read-only view: no copy, no lock, the project stays the same saved state, checked by file sizes and times, not byte for byte). `list` with `sha256` (or
   `programsOnly`) finds the program by hash; `open_program` it and check `info.sha256` before
   trusting answers.
3. **Ask.** `decompile`, `functions`, or `script` for anything else, bounded by `maxChars`. The
   program and its decompilers stay warm for the next client too.
4. **New binary.** `open_project` a working project with `"writable": true`, then `import` with
   `"analyze": true`. The same file is never imported twice.
5. **Change things** (names, types, bulk imports, version tracking) in a writable project that is
   a working copy, never in a master you want unchanged: `fork_project` the master, which other
   clients keep reading meanwhile, and write the fork.
6. **Errors.** `busy`: retry, or raise `wait`. `not_owner`: annotate your own overlay (the
   answer's `overlaySuggestion` is a ready request), join the writers when `suggest` is
   `share`, or use your own working copy (`suggestion` is a ready `fork_project` request).
   `conflict` with `reason: "changed"`: re-read the value and decide again.
   `unsaved_changes`: `save`, or close with `discard`.

## Pinning and upgrading

An integrator (an MCP server, an agent harness) should not copy `ghidra_session.py` from `main`
and hope the protocol still fits. Each release ships the client as its own file, next to the
engine, with checksums:

- `hydra-engine-<version>-win_x86_64.zip`: the headless install.
- `hydra-client-<version>.zip`: `ghidra_session.py` (standard library only, `CLIENT_VERSION` and
  `HYDRA_RELEASE` inside), `LICENSE` and a short `README.txt`. The file inside is the one in
  `support/` of the same release, with only `HYDRA_RELEASE` stamped.
- `SHA256SUMS`: both zips.

`<version>` is `<Ghidra version>-hydra.<n>`, for example `12.3-hydra.1`.

**Pin** a release: download both zips, check them against `SHA256SUMS`, and keep the engine and
the client of the same release together. `python ghidra_session.py version` prints
`{"client", "protocol", "release"}` of the client; `hello` (and `status`, and the endpoint file)
tell the engine's side:

| Field | Meaning |
|---|---|
| `protocol` | The wire protocol (an integer, now 2). Must be equal on both sides. |
| `minClient` | The oldest client library (`major.minor.patch`) this engine accepts. |
| `hydraVersion` | The Hydra Engine release, for example `12.3-hydra.1` (`12.3-hydra.dev` for a build from the tree). |
| `ghidraVersion` | The Ghidra version it is built on (also in `ghidra`). |
| `installId` | 16 hex digits, stable for one installation (directory, Ghidra build, release): tells two installs apart and a restart from a different install. |
| `startedAt`, `pid` | When this daemon started; its process. Together with `installId` they identify one daemon. |

**Fail on mismatch.** `ghidra_session.py` checks the `hello` answer on every connection and raises
`IncompatibleError` (a `LaunchError`; exit code 4 on the command line) when the protocol differs
or its `CLIENT_VERSION` is older than `minClient`, closing the connection first. The message
names both sides. `status`, `stop` and `kill` still work on such a daemon, so it can be stopped.
A client in another language should do the same with the fields above: refuse when `protocol`
differs, or when its own version is older than `minClient`. An engine that sends no `minClient`
(the `legacy-12.1.4` branch, which predates the contract) is accepted when its protocol matches.

**Versioning rules.** `protocol` changes only when a request or an answer changes shape
incompatibly. `CLIENT_VERSION` follows `major.minor.patch`: a new major means a protocol change;
a new minor, something added; a patch, a fix. `minClient` is raised only when an older client
would misbehave against the new engine. New fields in answers and new optional request fields
are additions and need neither.

**Upgrade.** Read the release's `CHANGELOG.md` section, then: stop the old daemon (`stop`), put
the new engine and the new client side by side, point your tool at them, run `version` and
`ensure`, and check `hello`. The daemon of an instance that runs another install is refused with
a clear error until it is stopped (use another `--instance` to run two at once). When Hydra's
Ghidra base changes, the release's version changes with it (`<new Ghidra version>-hydra.1`) and
its notes say what that does to saved projects.

## Projects analysed with Ghidra 12.1.4

What `main` does with a project that Ghidra 12.1.4 saved (the differences are in the databases:
the program database is version 33 on `main` and 32 in 12.1.4; the data type database is 3 and 2):

- **Read-only (the default):** works and writes nothing to the project. Each open upgrades the
  program in memory, which for a large one takes many times longer than the open itself, so the
  **upgrade cache** (above) builds an upgraded copy outside the project, in the background, and
  later opens read from it (`cachedUpgrade`, `cacheBuild` in `open_program`). The copy is
  block-cloned where the file system can, and the project stays the same saved state (checked by file sizes and times, not byte for byte).
- **Writable:** `open_program` with `"writable": true` is refused with `conflict` ("needs a
  database upgrade") until the request passes `"upgrade": true`. The upgrade is **one-way**:
  once `main` has saved the program, Ghidra 12.1.4 (and 12.2) can no longer open it, because
  they read database versions 32 and 2. Do it in a copy of the project.
- **`legacy-12.1.4`:** a branch with the same module on Ghidra 12.1.4, for projects that must stay
  on 12.1.4 and for comparing old and new analyses side by side (run it as its own
  `--instance` from its own install). It is a snapshot: it has the protocol 2 of that time but
  not the upgrade cache, the deferred start-up, or the contract fields above. The current client
  accepts it (the protocol matches and it sends no `minClient`; this pairing is not covered by
  the test suites), but features added since then are absent.

## Performance

### Parallel imports

`daemon_tests.py import_speed`: the same files, each into its own new project from its own
client, all sent at once, to a daemon with `maxImports` 1 and then N. Windows 11, 24 threads,
64 GB, Dev Drive, default heap; Windows 11 system binaries.

| Files | `maxImports` 1 | `maxImports` N | Peak heap (used), 1 / N |
|---|---|---|---|
| 4 PEs, load only: `mshtml.dll` 22.9 MB, `edgehtml.dll` 24.8 MB, `Windows.UI.Xaml.dll` 17.1 MB, `ntoskrnl.exe` 12.5 MB | 165.1 s | **63.9 s** | 1.5 / 3.0 GB |
| 2 random 128 MB raw files (mostly disk writes) | 15.6 s | **8.8 s** | 0.8 / 0.9 GB |
| 2 PEs with `analyze: true`: `wmp.dll` 10.1 MB, `onnxruntime.dll` 10.2 MB | 340.4 s | **320.1 s** | 5.7 / 5.9 GB |

With analysis the gain is only the second load's 33 s: the analyses (290-320 s each) already
overlapped with `maxImports` 1, because the gate covers the load and the save. Run directly
(`ProgramLoader` and `AutoAnalysisManager` in one script, no gate), the two analyses took 314 s
side by side against 605 s one after the other, each as long as alone, and gave identical
programs (functions, instructions, defined data, symbols, memory blocks). One run of the same
script while a 22-worker Gradle build saturated the machine gave each analysis twice its time
and different symbol counts (134,506 against 190,423 for `onnxruntime.dll`): Ghidra's analysis
results depend on time when the CPU is oversubscribed (timed analyzers such as the decompiler's
give up), with or without parallel imports, so keep `maxLong` within the CPUs you can spare.

Readers (`import_readers`, 60 functions of `choice.exe` decompiled again and again in the
project that two 128 MB raw imports write into): median **5.7 ms** before, **4.9 ms** during
(1,740 decompiles), 4.9 ms after.

### Ghidra master (12.3 DEV) against 12.1.4, same machine, same hour

Windows 11, JDK 25.0.4, 24 threads, 64 GB; the installs and projects on a USB NVMe Dev Drive
(ReFS); fast mode, AOT cache (trained on the program below) and class search cache on, 8 GiB
heap; the same 66.7 MB x64 executable with 243,855 functions, opened read-only, each build from a
project in its own database format. Each round runs every column once, in alternating order,
after one discarded warm-up round, so the columns share the machine's state; medians of 9 rounds,
ranges min-max. "master" is the module on master before the changes in "Changes outside this
module" and "Deferred start-up"; "this branch" is with them.

| | 12.1.4 | master | this branch |
|---|---|---|---|
| Launch until `ready` | 394 ms (386-704) | 504 ms (493-770) | **348 ms** (339-603) |
| `open_program` (243,855 functions) | 817 ms (794-1393) | 4126 ms (3730-6705) | **847 ms** (826-1144) |
| First `decompile` | 253 ms | 258 ms | 256 ms |
| **Launch until the first answer** | 1526 ms (1503-2176) | 4975 ms (4545-7836) | **1521 ms** (1482-2113) |
| Daemon: start it and connect | 578 ms (532-1077) | 685 ms (623-720) | **533 ms** (472-572) |
| Daemon: first client's `open_program` | 803 ms (782-979) | 4111 ms (3898-6478) | **832 ms** (754-869) |
| Daemon: start until the first answer | 1684 ms (1624-2392) | 5049 ms (4892-7491) | **1637 ms** (1589-1765) |
| Warm `decompile` (the benchmark function; about 1 to 45 ms by function size) | 7.0-7.3 ms | 7.1 ms | 6.7-7.1 ms |

The warm `decompile` rows here and below time one function of this program, whose size was not
recorded; a warm decompile depends on the function's size. Measured by the owner on a KotOR
executable (2026-10-27): 0.7-2.1 ms for a one-byte function and 35-45 ms for a 6.7 KB function of
29 basic blocks. Read "about 7 ms" as the benchmark function in one program, not as a constant.

Master's `open_program` cost depends on the volume the install is on: it is the language service
opening a lock file per language (see "Changes outside this module"), which measured 1.1-1.9 s
earlier the same day and 3.7-6.9 s here, on the same drive.

Tried and not kept (same method, paired against this branch, 8 rounds): `-XX:TieredStopAtLevel=1`
starts 48 ms sooner but lists all 243,855 functions in 43-50 s instead of 18-36 s, too slow for a
long-lived daemon; the parallel collector (+34 ms to the first answer), no compact object headers
(+25 ms) and `-Xms2g` (+104 ms) gained nothing. The decompiler is a native process, so a JVM
class data cache cannot help its start.

A project saved by 12.1.4 opens read-only on master without being changed, but every read-only
open upgrades the program in memory first: `open_program` then took 21-24 s for this program
instead of about 1.4 s. The upgrade cache (above) now does that once. Opening it writable is
refused until the request passes `"upgrade": true` (the upgrade is one-way; older Ghidra versions
cannot open the result).

### Ghidra 12.1.4 (the first measurements)

Measured on Windows 11, JDK 25.0.4, Ghidra 12.1.4, 16-core i7-13700KF, 64 GB, Dev Drive (ReFS);
the program is a 66.7 MB x64 executable with 243,855 functions in a 1.49 GB analysed project,
opened read-only. Medians of 5 runs (3 for the daemon start); the machine was also running other
heavy builds, so single runs vary.

**One new process per session** (what every caller paid before the daemon):

| | `.bat` launcher (before) | `standard` | `fast` | `fast` + AOT cache |
|---|---|---|---|---|
| Launch until `ready` | 1746 ms | 1408 ms | 689 ms | 468 ms |
| `open_project` | 75 ms | 73 ms | 86 ms | 41 ms |
| `open_program` (243,855 functions) | 1189 ms | 1234 ms | 1234 ms | 888 ms |
| First `decompile` | 284 ms | 298 ms | 288 ms | 250 ms |
| Warm `decompile` | 8.0 ms | 8.2 ms | 8.9 ms | 8.1 ms |
| **Launch until the first answer** | **3297 ms** | 3018 ms | 2318 ms | **1645 ms** |

Where the start-up time went: the `.bat` route runs `LaunchSupport` in three extra JVMs (about
0.3 s) and goes through `cmd`; the class search took about 0.6 s; without a custom system class
loader the AOT cache loads Ghidra's classes already parsed and linked. The AOT training run takes
about 26 s once per install and JDK.

**The daemon** (fast mode, AOT cache, class search cache):

| | |
|---|---|
| No daemon running: start it and connect | 573 ms (the JVM is ready after 413 ms) |
| First client: `open_project`, `open_program`, first `decompile` | 44 ms, 981 ms, 250 ms |
| Warm `decompile` (the benchmark function; about 1 to 45 ms by function size) | 6.3 ms |
| Another harness process, while the first is connected: connect + `hello`, join the project, `open_program` (already open), `decompile` | 14 ms, 0.9 ms, 0.9 ms, 7.4 ms (the benchmark function) |
| A harness that arrives after everyone left (within `keepWarm`): `open_program` | 1.7 ms (no reopen) |
| 40 decompiles of different functions by one harness | 0.2-1.2 s |
| Heap in use with that program open | 79-327 MB of a 15 GB ceiling |

So a harness pays the cold start once per machine, not once per question or per process; later
clients find projects, programs and decompilers already warm. For comparison, an
`analyzeHeadless -process ... -readOnly -postScript` run (stock Ghidra 12.1.4) doing one decompile
on the same project took 7.0-7.8 s per question and needed a copy of the project.

## Tests

- `examples/characterization_tests.py`: the exact JSON replies of every command (317 requests in
  seven scenarios: nothing open, a read-only project, edits, two clients, fork and refresh,
  overlays, import and scripts, with the errors of bad input and `busy`/`conflict`/`not_owner`
  naming the holder), compared byte for byte, key order included, with the golden files in
  `examples/characterization/`. It needs no binary (it writes two tiny PE files) and is the safety
  net for refactoring the Java; see [ARCHITECTURE.md](ARCHITECTURE.md) for the procedure and for
  what it does not cover.
- `examples/session_smoke.py`: the functional smoke test, through the daemon: create a project,
  import and analyse two programs, deduplicate, switch, decompile, rename, save, reopen read-only,
  contained scripts, ownership, busy, cancel and disconnect.
- `examples/contract_tests.py`: the integration contract, with no binary needed: the identity
  fields of `hello`, the endpoint file and `status` (stable `installId` over a restart); the
  client refusing a protocol or `minClient` mismatch (a daemon started with
  `-Dghidra.session.minClient=99.0.0` is the test hook) while `status` and `stop` still work; and
  the export contract of "Scripts": 600,000 lines (about 55 MB) written outside the project by
  `examples/scripts/ExportJsonl.java` with throttled progress, the job and its `artifact` visible
  in `status`, `maxChars` not capping the file, and a cancel and a daemon shutdown each leaving a
  valid partial file.
- `examples/daemon_tests.py`: two harness processes starting the daemon at once, several
  projects in one daemon, a DLL import, a client killed while it owns a program and analyses it,
  the daemon killed and restarted, fair scheduling, `cancel all`, idle shutdown, warm programs,
  the import queue (with `maxImports` 1, two and three concurrent imports: a queued one
  cancelled, the running one cancelled and the next starting, re-ordering; `--raw-mb` sets the
  size of the random raw files it imports), what concurrent loads share (`import_isolation`),
  parallel imports (`parallel_imports`: into two projects at once, two files into one project
  and one new folder, the same file twice at once imported once, a running import cancelled
  while the other completes; `import_kill`: a client killed mid-import, its import stopped with
  no program or temporary file left while another client's import completes, and the daemon
  killed with two imports running, after which the project holds no partial program and the
  files import again; `import_readers`: decompile latency in a project before, during and after
  two imports into it; `import_speed`: the same binaries with `maxImports` 1 and N, wall time,
  peak heap and identical programs, on `--big <binary>` (repeat) or two random raw files,
  `--big-analyze` to analyse too), per-request labels (the
  holder in a `busy` answer names the label, cancel scoped per label),
  a private stdio session, and the upgrade cache (a current program does not use it; with
  `--legacy-project`, a project saved by an older Ghidra, best a small one, which the test
  block-clones first: an opted-out daemon upgrades in memory; the first open takes in-memory time
  and starts the build; two concurrent opens make one build; after the build a reopen comes from
  the copy and is faster; a daemon killed mid-build leaves no entry and the next start builds
  cleanly; a stop mid-build is prompt; a queued build waits for a client's long job, fails when
  the source changes meanwhile, and the next open retries; `cancel` stops a build; an older key's
  copy is removed; the source's files keep their sizes and times); `holders` (who holds what, in `busy`, `conflict` and
  `not_owner`, and the suggested action); `fork` (a fork while the master's view stays open and
  in use; its sidecar; a fork of a fork; unsaved changes, an existing destination, a source
  another client or process writes, refused; `copy-on-write`, `auto` and `full` modes; the master
  keeps its files' sizes and times); `revisions` (revisions in `open_project`, `open_program`, `info` and
  `status`; another process saves: `stale` on the readers' next answers; one reader's `refresh`
  switches both, the other is told once with `refreshed`; a fork starts at its source's revision;
  a writable project needs no refresh); `overlays` (two clients' overlays of one program show
  different names while a third client and the owners' plain view see the canonical program; an
  overlay is private; a failing operation rolls back its whole call; a signature and a data type;
  a killed owner's overlay is dropped and the shared program is untouched; `promote_overlay` into
  a fork; a refresh rebuilds overlays; `drop_overlay`); `multi_writer` (a writable open while a
  reader holds the view reopens it in place; a second writable open joins; two writers rename,
  comment, analyse and save two programs of one project at the same time; `not_owner`
  alternatives; the project reopens with both writers' work); `shared` and `shared_stress`
  (see "Shared writing"); `edit` (three operations in one call, journalled; a stale `expect` or
  a bad operation refuses the whole call, naming the last editor; a non-writer is refused;
  `discard_edits` deletes the labels an author created and reverts its rename and comment while
  keeping the others'; the project reopens with exactly the kept changes); `overlay_owned` (a
  client refused with `not_owner` takes the suggested overlay of a program another client owns
  writable; the owner saves twice while it is open; nothing of it reaches the owner's program or
  the saved project); `refresh_force` (`force` reopens an unchanged view for all its clients and
  rebuilds their overlays; the project is not written); `legacy_overlay` (with
  `--legacy-project`: an overlay opened while the upgrade cache build waits, then one from the
  finished copy); `orphan_shutdown` (orphaned shared-write work kept until the daemon stops,
  which discards and logs it); `import_write_kill` (the daemon killed while an import writes its
  program into the project, at the first sight of the new database and part-way through: the
  program is absent or complete, never half, and the file imports again).

```
python examples/characterization_tests.py --ghidra <install> --work <empty dir> [--record]
python examples/session_smoke.py --ghidra <install> --work <empty dir> --binary A.exe --binary B.exe
python examples/daemon_tests.py --ghidra <install> --work <empty dir> --exe A.exe --dll B.dll [--project <analysed project>] [--legacy-project <older project> [--legacy-program <path>]] [--big <binary>]... [--big-analyze]
python examples/contract_tests.py --ghidra <install> --work <empty dir> [--lines 600000]
```

Both use their own state dir and daemon instance, so they never touch the user's daemon.

`daemon_tests.py` run serially takes 25 minutes or more, and the machine is idle most of that time (the tests wait
on timers, kills and restarts). `examples/run_parallel.py` runs it as a work queue: every test (and every shard of
the long ones, `name@shard`, reported under the test's name) is its own `daemon_tests.py --only ...` process with its
own work, temp and state directories, longest first:

```
python examples/run_parallel.py --ghidra <install> --scratch <dir on an NVMe disk> --logs <log dir> daemon_tests.py -- --exe A.exe --dll B.dll [--legacy-project <older project>]
python examples/run_parallel.py ... --affected [--base integration/w3] daemon_tests.py -- ...
python examples/run_all.py --ghidra <install> --scratch <dir> --logs <dir> [--only daemon,cc,smoke,char2,char3,contract]
```

* The fixture project, the class search cache and a copy of the install are made once (`daemon_tests.py --prepare`)
  and kept in `seed-cache` next to `--scratch`, keyed by the install's jars and the suite's code; every test copies
  or hard-links them instead of making its own.
* The test daemons are lean JVMs (two GC threads, two compiler threads, and C1 only for the tests that are not in
  `suite-costs.json`'s `daemon_tests.py#heavy` list; `--full-jvm` turns this off), and each test process has its
  own Ghidra settings dir (`XDG_CONFIG_HOME`): with the user's one shared, every daemon contends for its OSGi bundle
  cache and a script request took seconds instead of milliseconds.
* The queue starts a test while the running ones' core demand stays within `--cores` (default 22; a test counts
  `--light-cores` 1, a heavy one `--heavy-cores` 2, and at most `--heavy-slots` heavy ones run), the machine has
  `--min-commit-gb` of commit left (Windows refuses new processes, exit 0xC0000142, when the commit runs out) and
  fewer than `--max-procs` processes. `<logs>/machine.csv` has the busy cores, the running tests and the commit
  every 2 s.
* `--affected` runs only the tests `examples/test-map.json` maps the changed files to (`git diff <base>...HEAD`
  and the working tree), plus a smoke set of 10; it prints what it skipped and why, and runs the whole suite when a
  changed file is a core one (Session, Scheduler, Access, the protocol dispatch, the launcher, ...) or is not in the
  map. The map is made by static analysis (`run_parallel.py --make-test-map`; `--selftest` checks it is current
  and covers every test). Iterate with `--affected` or single tests; run the whole suite once before calling a
  change done.
* `run_all.py` puts the other suites (client_compat, session_smoke, characterization p2 and p3, contract) in the
  same queue.

A test that fails under that load is run again alone; it fails the run only if it fails alone too (`--strict` fails on
both). A test process that dies, or a test with no result, fails the run. Costs for the balancing are in
`examples/suite-costs.json` (`--record` refreshes them). Put `--scratch` on a fast local disk: the suites write and
fsync a lot, and on a hard disk they are slower and more timing-sensitive. The default budget takes the whole machine:
on a machine shared with other heavy work, run one suite at a time or lower `--cores`.

## Why each part lives where it does

| Part | Where | Why |
|---|---|---|
| Version tracking, bulk types, structure from usage, re-analysis, labels | Ghidra's public Java API, called from a script | Already there and already headless; see the table below. Nothing to fork. |
| Session, daemon, projects, programs, scheduler, locking, transports | This module (`Features/HeadlessSession`) | It has to live in a JVM that has Ghidra initialised and holds the open `Project` and `Program` objects across requests. |
| Read-only project view | This module | `DefaultProjectData`'s read-only constructor is public, but `analyzeHeadless` never uses it. Using it needs a `DefaultProject` subclass (`SessionProject`), which is module code. |
| Class search cache | This module (`SessionApplicationConfiguration`) | A subclass of the headless configuration seeds `ClassSearcher` through two private fields, reflectively; if they are missing it turns itself off. |
| Launcher, daemon manager, client | `support/ghidra_session.py` in this module | Platform-agnostic, no shell. The distribution copies a module's `support/` into the install, so it ships with the module. |
| Anything specific to one client (an MCP server's tools, its stores and checks) | That client | The session is a generic Ghidra front end. Clients call it; they do not contain it. |

The module needs nothing private from Ghidra beyond three reflective touches
(`HeadlessScript.setHeadlessInstance`, `ClassSearcher`'s search result, and `ProgramDB`'s
`DB_VERSION` for the upgrade cache), each optional: without it that feature turns itself off.

## Changes outside this module

Five changes in Ghidra itself and one added class, each found by this module's measurements or
tests, each small and each useful to any Ghidra process:

| Where | Before | After |
|---|---|---|
| `Framework/DB`, `LocalBufferFile.close`/`delete` | A temporary buffer file (a program's database cache) is closed, then deleted. On ReFS (a Windows Dev Drive) the last close of a file writes all its dirty cached pages back to disk first, even when the file is deleted right after: closing a large program, or shutting a session down with one open, took 22-41 s with `java.io.tmpdir` there (up to 150 s seen), against 0.05 s on NTFS. | A temporary file is truncated to 0 bytes before it is closed, which drops its unwritten pages: 0.25-0.76 s on the same drive. Nothing reads it again, so nothing else changes. |
| `Framework/FileSystem`, `LocalDatabaseItem.create` | A new program written into a project (an import's save, *Save As*) gets its item's property file, with its file type, first; then its database is streamed in. A process killed during that stream (measured: a 512 MB raw import killed 30% into a 10 s write) leaves an item that every later open lists as a program and fails to open ("Unrecognized file format"). | The property file is written without its file type until version 1 of the database is complete (the existing `versionCreated` callback adds it). An item killed mid-write has no file type, which Ghidra's existing repair removes the next time the folder is listed ("Removing folder item with unspecified file type"); a completed one is unchanged. Only new private (non-versioned) databases; shared-project (server) files are untouched. `daemon_tests.py import_write_kill`. |
| `Framework/DB`, `LocalManagedBufferFile.saveCompleted` | A save writes the new version file under its final name (`db.N.gbf`) and only then writes and syncs its header. A process killed in that window leaves a final-named version file with an empty header, which Ghidra cannot open ('Unrecognized file format'), and a read-only open fails on it too. Measured on the crash tests: 12 of 363 killed saves. | The header is written and synced before the rename, so a killed save leaves either the old version or a complete new one. Kill batches since then: 0 unopenable versions in 200 kills on NTFS (`daemon_tests.py e8_kill_loop`), a bounded result, not a guarantee. No ReFS result is stated: ReFS is not tested for hydra.4 (owner decision 2026-10-30, `PROTOCOL-3.md` 8.12). |
| `Framework/FileSystem`, `VersionedDatabase`, `LocalDatabaseItem` (open) and the added class `VersionFileCheck` | An unreadable newest version file (left by an older build, or by a kill outside the window above) makes the whole database unopenable. | The newest version is checked when a database is opened. A writable item inside a root declared disposable (`hydra.storage.repairRoots`) moves the bad file aside (`.quarantine`) and uses the previous version; any other open, and every read-only open, writes nothing and answers `corrupt_newest`. The daemon does not declare roots yet, so today a real fork is not repaired; that comes with the fork and health work in `PROTOCOL-3.md`. |
| `Framework/SoftwareModeling`, `SleighLanguageFile` | On master, the language service opens a `<language>.sla.lock` file read-write for every language definition (about 300) when it starts, only to learn whether it could lock it. Each open and close of a file on the install's volume costs milliseconds, more on a volume with an antivirus filter: the first `open_program` of a session took 1.4-6.9 s instead of about 0.8 s. | The lock file is created the first time a language actually needs it (`canLock`, `withLock`): one or two per session. Same results, same rules for a directory the user cannot write. |

The distribution also leaves out `__pycache__` folders and `.pyc` files that running a module's
`support/` scripts from the source tree leaves behind (`gradle/distributableGhidraModule.gradle`).

## What is already scriptable (Ghidra master, 12.3 DEV)

| Ghidra feature | API, headless | Verdict |
|---|---|---|
| Version tracking | `VTSessionDB.createVTSession` (`Features/VersionTracking/.../api/db/VTSessionDB.java:116`), `VTProgramCorrelatorFactory.createCorrelator` (`.../api/main/VTProgramCorrelatorFactory.java:68`), `AutoVersionTrackingTask(VTSession, ToolOptions)` (`.../gui/actions/AutoVersionTrackingTask.java:96`; runs with default options and needs no tool); `ghidra_scripts/AutoVersionTrackingScript.java` already branches on `isRunningHeadless()` | Script. What headless lacks is two programs open in one long-lived process; the session supplies that. |
| Bulk types | `CParserUtils.parseHeaderFiles` (`Features/Base/.../cparser/C/CParserUtils.java:402`, returning a `FileDataTypeArchive`; the `FileDataTypeManager` variants are deprecated since 12.3), `DataTypeArchiveFactory.createFileArchive` / `openReadOnly` / `openForUpdate` (`Framework/SoftwareModeling/.../database/dtarchive/DataTypeArchiveFactory.java:49,121,160`), `DataTypeManager.addDataType` / `addDataTypes` (`.../data/DataTypeManager.java:133,147`); `EnumDataType`, `UnionDataType`, `TypedefDataType`, `FunctionDefinitionDataType` | Script. |
| Auto create structure | `FillOutStructureCmd(ProgramLocation, DecompileOptions)` (`Features/Decompiler/.../util/FillOutStructureCmd.java:56`) takes a `VariableLocation` or `FunctionParameterFieldLocation`, not only a decompiler click; `FillOutStructureHelper.processStructure` (`FillOutStructureHelper.java:106`) | Script. |
| Re-analysis | `AutoAnalysisManager.getAnalysisManager`, `reAnalyzeAll(AddressSetView)`, `startAnalysis(TaskMonitor)` (`Features/Base/.../analysis/AutoAnalysisManager.java:948,325,604`; it runs in the calling thread when there is no tool) | API, and the `analyze` command. |
| Data labels, global renames, bookmarks | `SymbolTable.createLabel`, `Symbol.setName` / `setNameAndNamespace`, `DataUtilities.createData`, `BookmarkManager.setBookmark` | API, and the `rename` command. |
| Several programs and projects, switching, checkout, save | `Project`, `ProjectData.getFile`, `DomainFolder.getFiles`, `DomainFile.getDomainObject` / `getReadOnlyDomainObject` / `checkout` / `save` | The API exists. `analyzeHeadless` exposes one program per run and always takes the project lock. **This is the part that needed new code: this module.** |

## Limits

- Tested on Windows 11 (locally and in CI); releases are Windows x64 with JDK 25 only. The
  launcher and module have no Windows-specific path (POSIX file locks, `start_new_session`,
  owner-only state dir), but no Linux or macOS claim is made: they are not tested.
- There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by Ghidra
  12.2 or 12.1.4. Projects saved by this build (upstream `master`, 12.3 DEV) write data type
  databases at version 3, which those versions cannot read. A read-only view writes nothing;
  open an older project writable (or `fork_project` it and write the fork) only when it may move
  to this version.
- An overlay changes only through its five operations (`rename`, `label`, `comment`,
  `signature`, `data_type`), and it is over the program as it was stored when the overlay
  opened: it does not show an owner's or shared writers' unsaved changes, nor saves made after
  it opened (a `refresh` of a read-only view rebuilds it on the new revision; on a writable
  project, drop and reopen it).
- A fork is a block clone only on ReFS (Windows 11 24H2 and later); elsewhere it is a full copy,
  which `auto` refuses above `forkCopyLimitMb`.
- Shared writing journals renames, labels, comments, `edit` operations, analyses and scripts,
  but `discard_edits` reverts only renames, labels and comments; the journal keeps the last
  200,000 entries per program and lives in the daemon's memory while the program is open (it is
  not saved with the program).
- The AOT cache needs JDK 25 or later (`-XX:AOTCacheOutput`); older JDKs run without it.
- A read-only view does not pick up changes saved to the project by another process after it was
  opened until a client sends `refresh` (its clients are told with `stale`).
- With `tmpdir` on a ReFS volume (a Windows Dev Drive), writing Ghidra's buffer cache is slower
  than on NTFS (ReFS writes a file's dirty pages back when its last handle closes), so an
  in-memory upgrade or a large analysis is slower there. Closing is fixed (see "Changes outside
  this module"), and so is removing the cache files a killed daemon left behind (the session
  truncates each one first, in the background); put `tmpdir` on a fast NTFS or ext4 disk with
  room if you can.
- At most `maxImports` imports run at once (default one per four CPUs, 1 to 4), each holding
  its program in memory until it is saved; more queue, visibly. The library search path set
  that loaders use to find libraries is one per process, not per project (as it always was);
  see "Parallel imports".

### Limits of 12.3-hydra.4 and protocol 3

These are the limits of [`PROTOCOL-3.md`](PROTOCOL-3.md), section 6.2, one by one (L1 to L19, then the
eleven "revision 6" limits R6.1 to R6.11). Some belong to the client (Hydralysis); they are listed
here so that the list is complete in one place. The guarantees the release may state are only those of
section 6.1, each with its test; until a gate of section 9 has passed, nothing below is stated as passed.

- **L1, non-cooperative threads.** Java cannot kill a thread that ignores cancel and interrupt, nor
  release a `ReentrantReadWriteLock` from another thread. A script that never polls
  `monitor.checkCancelled()` keeps its program lock after its client is gone. The engine bounds the
  wait, shows the holder and keeps the rest of the daemon running; restarting the daemon is safe for
  Hydralysis work (its store is the record). Only a helper JVM for user scripts is a hard remedy: that
  is the script worker (E7, `isolation:"worker"`), and its release gate (9.14) has not passed as a
  whole, so the documents say such a script is bounded and quarantined: confined to its owner's
  view and one slot, counted against the owner's cap.
- **L2, the overlay lifecycle waits are not cancel-aware.** `openOverlay`, `rebuildOverlays`,
  `dropOverlays` and `promoteOverlay` take untimed locks on an overlay's lock. `cancel`, a `timeout`
  deadline and the release of a dead client do not reach a request blocked there. What `cancel` and a
  `timeout` end are the request-bound timed lock waits (a program, a project, or an overlay's request
  lock site: V5).
- **L3, a stalled call on hydra.2 or hydra.3 is abandoned, not ended.** On those engines the client's
  deadline sends `cancel`, then abandons a worker thread and its connection; the engine keeps the
  request, its slot and any lock until it ends by itself, and a script that never polls its monitor can
  hold them for as long as it runs. Hydralysis tolerates at most 8 abandoned user connections per
  process (its supervisor probe has its own budget of 3), and each stays a `users` entry of the programs
  it joined until its request ends. The remedy is hydra.4's bounded release of a dead client.
- **L4, a leave can stall the other readers of a program.** On hydra.2 and hydra.3 the release of a
  client takes the program's exclusive lock; while it waits behind a running read, every new
  `open_program`, script or decompile of that program waits behind it, up to the longest running read
  (at most its `timeout`), and a waiter whose own `wait` is shorter gets `busy`. On hydra.4 a plain
  reader's leave takes no exclusive lock (V10), but the leave of an owner or writer of an open (legacy)
  program still queues the exclusive lock, bounded by `cleanupGraceS + abandonWaitS`. The stall is
  bounded and visible (`busy` with the holder), not a hang or a loss.
- **L5, the `lane:"quick"` hint is trust-based.** The engine cannot know that a script is quick. It
  honours the hint for `0 < timeout <= quickScriptMaxS`, and the `timeout` only sets the request's
  cancel flag: a script that never polls `monitor.checkCancelled()` keeps its quick slot past its
  timeout, and enough of them use up the quick lane. RusticQuery polls and is hash-pinned; an arbitrary
  user script that claims `quick` is not policed. `health` shows it (`longestRunningMs` past the hint).
- **L6, history is capped by records and bytes** (Hydralysis). A store with 4096 pending records, or
  20 MiB of them, takes no further edit until some are committed (a subset commit works) or exported as
  a bundle; pending records are not compacted and nothing is dropped automatically.
- **L7, an append log has no rotation yet** (Hydralysis). A `CURRENT.log` or `backups.log` is read in
  full by the lineage open, `verify` and the doctor, which is linear in its size (one line per commit or
  backup).
- **L8, copy-on-write is ReFS only.** On NTFS a fork is a full copy bounded by `forkCopyLimitMb`. No
  ReFS behaviour is tested for this release: the release machine has no ReFS volume (owner decision
  2026-10-30, `PROTOCOL-3.md` 8.12); NTFS is the release file system. A clone backup is not protection
  against the loss of the volume.
- **L9, Windows x64 and JDK 25 only.** No Linux or macOS claim is made.
- **L10, no power-cut test.** Durability rests on documented flags (fsync, write-through), process
  kills (`TerminateProcess`) and torn-file tests. Directory-entry durability cannot be forced from Java
  or Python on Windows; the design does not rely on it (every state is self-validating and a reader
  takes the last valid record). Nothing is claimed about power loss or an OS crash.
- **L11, `Revision.of` is metadata for large files** (size and modification time above 1 MiB): it
  shows that the saved state is the same, not that the bytes are intact. Integrity is the manifest hash.
- **L12, a backup verifies the bytes it reads back through the OS cache after a flush**, not the
  media. Latent errors are found by re-hashing (`backend backups verify` in Hydralysis) and by keeping
  an independent copy.
- **L13, bulk edits have no per-subject `before`** (`import_types`, `import_archive`): drift is
  detected by the input hash. A subject is an address, a type path or `structure:functions`; a struct
  and a prototype that uses it are different subjects, a dependency the rebase cannot see. The same
  holds for a subset commit (`only`): it can ship a `signature` or `data_type` edit without the pending
  struct it uses. Subset commits have no semantic dependency tracking.
- **L14, the upgrade gate and the backup check are guards against accidents**, not a security
  boundary: a local process with the daemon's rights can forge a manifest.
- **L15, `private` isolation reads the stored file**, not unsaved edits; in `shared` isolation
  `attemptedChanges` is program-wide, not per script.
- **L16, an ETA is a rough estimate**: `null` without history, and `null` when the lane is dominated
  by a long job.
- **L17, headless only.** There is no GUI. Projects Hydra Engine writes cannot be opened by Ghidra 12.2
  or 12.1.4, and opening them in a stock Ghidra is not a goal.
- **L18, the data-type database version** (`analysisIdentity.dbVersions.dataTypes`) is `null` when it
  cannot be read; it is never guessed.
- **L19, sources of numbers.** The save time (about 35 s) and the clone and hash costs come from the
  1.5 GB, 243,855-function benchmark; the golden baseline is KotOR (122 MB). Every timing constant of
  the design is unmeasured on the target machine until the measurements of release gate 9.10 are
  recorded.
- **R6.1** Every measurement behind the design (streams A, B, C and D) is a single run or a handful on
  one 24-CPU machine under foreign load (A varied about 2x between identical runs), on KotOR (8,966
  functions) only; heap per view, fork time, publish latency and the soak result do not transfer to a
  244k-function, 1.5 GB program.
- **R6.2** The kill tests are `TerminateProcess`: the OS page cache survives, so fsync and power loss
  are not measured.
- **R6.3** Kills inside the write window are rare at random times (2 of 131), so the batches use
  trigger-timed kills, a biased sample that gives bounds, not field rates; the intervals are wide
  (Wilson 95%).
- **R6.4** Open (legacy) projects, protocol 2 connections, rooms of shared writers and the shared view
  keep their locks and block their own readers; the non-blocking contract is for sealed generations
  and views.
- **R6.5** One `Program` instance serves DB-bound reads at 1.4x to 1.8x of one reader, until E11
  (hydra.5, conditional).
- **R6.6** A script that ignores cancel cannot be stopped until the script worker's gate (9.14) passes
  (L1).
- **R6.7** A native decompiler is one process per concurrent request. The decompiler gate of the
  resource governor (E9) is in this build, but its release gate (9.14) has not passed as a whole, so
  no bound on the number of decompiler processes is stated.
- **R6.8** The unmeasured values (heap watermarks, eviction times, quotas, `BASE_WAIT_S`) are starting
  points, to be checked by the squeeze laps of release gate 9.14.
- **R6.9** ReFS gives a disk saving and no protection (and nothing about ReFS is tested for this
  release, L8).
- **R6.10** Whether the version-file defect (the newest version unopenable after a kill during a
  save) also exists in stock Ghidra was not run.
- **R6.11** The foreign-load sampler that records how busy the machine was is an estimate.
