# Headless Session

`analyzeHeadless` is a command about one program file: it opens (and locks) one project, runs
pre/post scripts against the programs that `-process`/`-import` select, and exits. The Ghidra
window is a session: you open a project, see what is in it, pick a program, switch to another,
keep working, save, and the process stays.

The headless session is that session without the window, as a shared per-user service. One
long-lived JVM, driven by JSON lines over an authenticated loopback socket (or stdio), that:

- serves **any number of projects at once**, each opened in place by its `.gpr`, its folder, or a
  parent folder: read-only without touching the project, or writable when asked;
- serves **any number of clients at once** (several agent harnesses, tools, MCP servers), which
  find it through a per-user endpoint file and start it if it is not running;
- lists folders and programs, with each program's SHA-256, without opening them;
- opens and switches programs, also inside folders, **without importing**;
- imports any format a Ghidra loader accepts (PE EXE and DLL, ELF, Mach-O, raw, ...), never twice
  for the same SHA-256 in a project;
- runs auto-analysis on request, decompiles, renames, comments, saves;
- runs any GhidraScript (Java, or Python through a script provider) with arguments;
- shares work fairly: per-program read/write locks with one writer, a scheduler that keeps long
  work from delaying quick queries, per-client cancellation, and clean release when a client
  dies;
- stays up (or stops after an idle time you choose).

It is one new module, plus two small fixes to Ghidra classes that the session's measurements
found (see "Changes outside this module"). No launcher is changed, and there are no `.bat`, `.sh`
or PowerShell launchers: `support/ghidra_session.py` (Python 3.10+, standard library only, any
OS) starts the JVM itself.

## Quick start

```
python <ghidra>/Ghidra/Features/HeadlessSession/support/ghidra_session.py ensure
python <ghidra>/Ghidra/Features/HeadlessSession/support/ghidra_session.py call open_project path=C:/re/Game
python <ghidra>/Ghidra/Features/HeadlessSession/support/ghidra_session.py status
```

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
  protocol channel.
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
| `call CMD key=value...` | One request through the daemon; values are JSON when they parse (`writable=true`). |
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
| `maxLong` | | CPU / 4 (at least 2) | Concurrent long requests (analyze, import, script, save). |
| `scriptPath` | | `[]` | Extra GhidraScript directories. |
| `log` | | `<state>/<instance>.log` | The daemon's log (Ghidra's log and stderr). |
| `upgradeCache` | `GHIDRA_SESSION_UPGRADE_CACHE` (`off`, `false`, `0`: off) | `true` | Serve read-only opens of programs saved in an older database format from an upgraded copy (below). |
| `upgradeCacheDir` | `GHIDRA_SESSION_UPGRADE_CACHE_DIR` | `<state>/upgrade-cache` | Where those copies live; best on the same volume as the projects (a block clone there costs nothing). |
| `forkCopyLimitMb` | `GHIDRA_SESSION_FORK_COPY_LIMIT_MB` | `2048` | `fork_project` in `auto` mode refuses a full copy (one the file system cannot block-clone) larger than this; `"mode": "full"` copies anyway. |

The state dir is `--state`, else `GHIDRA_SESSION_HOME`, else per user:
`%LOCALAPPDATA%\GhidraSession` (Windows), `~/Library/Application Support/GhidraSession` (macOS),
`$XDG_STATE_HOME/ghidra-session` or `~/.local/state/ghidra-session` (Linux). It is created
owner-only on POSIX; on Windows it inherits the per-user ACL of its parent.

## The shared daemon

One daemon per user and **instance** (default `default`). Its files in the state dir:

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

By default a project is opened the way the window's *File > View Project* opens one: as
`new DefaultProjectData(locator, false, false)`, which takes **no project lock** and opens every
file system read-only. Nothing in the project is written: not a lock file, not an index, not a
timestamp. Any number of sessions, and a Ghidra window, can read the same project at the same
time, and there is no need to copy the project first.

`analyzeHeadless` cannot do this. It always opens the project through `DefaultProject`, which
calls `new DefaultProjectData(locator, true, ...)` and locks the project, even with `-readOnly`;
`-readOnly` only skips the save (`HeadlessAnalyzer.openProject` and its `HeadlessProject`;
`processFileNoImport` opens the program with `getDomainObject` and does not save it;
`DefaultProject.java:119`).

With `"writable": true` the project is opened with its lock, as the window's *Open Project* does.
Only one process can hold it; a second writable open gets `conflict` with the lock file's path.

A read-only view does not see changes another process saves to the project after it was opened;
its clients are told (`stale`, below), and `refresh` reopens it for all of them.

### Revisions and `refresh`

Every project and program has a **revision**, a 16-hex-digit fingerprint of what is saved:

- **Project revision**: every file of the `.gpr` and `.rep` by relative path, size and
  modification time, plus the SHA-256 of every file up to 1 MiB (the `.gpr`, property and index
  files): the identity the upgrade cache keys by, without the project's location and this
  Ghidra's version, and without `<name>.rep/projectState` (window and tool state Ghidra rewrites
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

A read-only view lets any number of clients read a project; only one may write it, and only
when nobody else uses it. A client that wants to change things while others keep reading forks
the project into a **working copy** of its own:

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
  writable in this daemon by another client (`conflict`, naming the `holders`), or locked by
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

### Overlays: a private annotation view of a shared program

**The need.** One client wants to try a name, a comment, a label, a signature or a data type
while other clients keep reading the same program; nobody else must see it, nothing may be saved
unless the client decides to keep it, and a client that dies or fails must not leave anything
behind in the shared program. A fork per hypothesis is heavier than that needs.

**Why not a view of the shared program.** Ghidra has no per-client view of one `Program` object:
a change in a program object is a change for everyone holding it, and the session shares one
object per program among its readers. Contained scripts get isolation only by rolling everything
back at the end, so they cannot keep a change for later requests.

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

One JSON object per line, UTF-8, `\n`-terminated, at most 64 MiB per line.

Request:

```json
{"id": 7, "cmd": "decompile", "program": "p1:/game.exe", "address": "rva:0x5d53a0", "wait": 10000}
```

- `id`: any JSON value; the response echoes it. Unique among this client's unanswered requests.
- `cmd`: the command.
- `wait`: milliseconds the request may wait for a scheduler slot or a lock before it fails with
  `busy` (default 10000). Nothing queues forever.
- `parallel`: `true` runs the request at once on its own thread. Without it, one client's
  requests run in the order sent (other clients always run in parallel). Use it when one
  connection carries several independent callers, as an MCP server's does.

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
| `status` | | Session identity (as `hello`), launch info, memory, projects, programs (mode, owner, users, what holds each lock, idle time), clients (`name`, `harness`, `clientVersion`, and their unanswered `requests`: `id`, `cmd`, `artifact`, `ms`, `message`, `progress`, `maximum`), overlays, scheduler lanes, upgrade cache builds. |
| `projects` | | Open projects, which ones this client joined, its active project. |
| `open_project` | `path`, `writable`=false, `discard`=false | Joins the project, opening it if needed. `path` is a `.gpr`, its folder, a `.rep`, or a parent folder with exactly one project at most two levels below. A read-only view is reopened writable only when no other client uses it; a read-only request on a writable project joins it. |
| `fork_project` | `project` (id or path), `path`, `name`?, `writable`=true, `mode`=auto\|copy-on-write\|full, `maxCopyMb`? | Copies the project into a working copy of this client's, opened and joined; the source and its read-only views are untouched. See "Working copies". |
| `close_project` | `project`?, `discard`=false | Leaves the project (closes this client's programs there). A writable project closes when its last user leaves; a read-only one after `keepWarm`. |
| `project` | `project`? | The project: id, name, paths, writable, files, users, programs, `revision`, `diskRevision`, `stale`, `generation`, and `fork` (its sidecar's summary) when it is a fork. |
| `refresh` / `reopen` | `project`?, `force`=false | Reopens a read-only view on what is saved now, for all its clients at once. See "Revisions and `refresh`". |
| `list` | `project`?, `folder`="/", `recursive`=true, `programsOnly`=false, `metadata`=true, `sha256`, `offset`, `limit`=1000 | Folders and files, with `key`, `sha256`, `language`, `format`, `executable` and `open` (who uses it) for programs; `sha256` finds a program by its hash. Paged, with `truncated`. |
| `open_program` / `switch` | `path` (path, unique name or key), `project`?, `writable`=false, `checkout`=false, `upgrade`=false, `wait`: `true` | Opens the program, or joins it if it is open (also a warm one nobody uses), and makes it active. Writable needs a writable project; a versioned file needs `checkout`. `"wait": true` on a read-only open of an older-format program waits for its upgrade cache copy instead of upgrading in memory (slot and lock waits keep the default). |
| `programs` | | This client's programs (all projects) and its active ones. |
| `open_program` + `overlay` | `path`, `overlay` | Opens the program read-only for this client and creates or joins its private overlay. See "Overlays". |
| `apply_overlay` | `program`?, `overlay`, `ops` [...] | Applies operations (`rename`, `label`, `comment`, `signature`, `data_type`) to the overlay, all or none, and logs them. |
| `drop_overlay` | `program`?, `overlay` | Drops the overlay. |
| `promote_overlay` | `program`?, `overlay`, `project` or `fork` {`path`, `mode`, ...}, `path`?, `save`=true | Replays the overlay's log into a writable copy of the program (a project this client opened writable, or a new fork) and saves it. |
| `overlays` | | This client's overlays. |
| `info` | `program`?, `overlay`? | Key, language, compiler, image base, format, executable path, SHA-256, MD5, functions, analysed, changed, mode, owner, users, `revision`, `projectRevision`, `generation`, `overlays` (this client's). With `overlay`: the program as the overlay shows it. |
| `close_program` | `program`?, `discard`=false | Drops this client's use. The owner of a changed program must `save` first or pass `discard`. |
| `functions` | `program`?, `contains`, `regex`, `offset`, `limit`=200 (max 10000), `overlay`? | Functions by name filter, paged. |
| `decompile` | `program`?, `address` or `name`, `timeout`=60 s, `maxChars`=200000, `overlay`? | C text and signature. Decompilers are pooled per program (and per overlay), so warm calls skip the start-up cost. |
| `rename` | `program`?, `address`, `name`, `kind`=auto\|function\|label, `overlay`? | Renames the function at the address, or creates or renames the primary label: data labels and global names. Owner only; with `overlay`, in the client's overlay. |
| `comment` | `program`?, `address`, `text` (null clears), `type`=eol\|pre\|post\|plate\|repeatable, `overlay`? | Owner only; with `overlay`, in the client's overlay. |
| `analyze` | `program`?, `options` {name: value}, `ranges` [[start, end], ...], `timeout` s | Sets analysis options, then runs auto-analysis on everything (or what the ranges trigger) the way `analyzeHeadless` does, and marks the program analysed. Owner only. |
| `save` | `program`?, `comment` | Owner only. |
| `import` | `file`, `project`?, `folder`="/", `name`, `language`, `compiler`, `analyze`=false, `duplicate`=false, `timeout` | Imports into a writable project with `ProgramLoader` (any format it accepts), saves it, opens it writable for this client, and optionally analyses and saves it. A file whose SHA-256 is already in the project returns `{"imported": false, "existing": [...]}` unless `duplicate`. |
| `script` | `script` (name on the script path, or a file path), `args` [...], `program`? (null: none), `project`?, `address`, `exclusive`=false, `save`=false, `timeout` s, `maxChars`, `artifact` (a path the script writes; echoed in `status` and the result) | Runs a GhidraScript and returns its `println` output. See "Scripts". |
| `cancel` | `target` (an id of this client's request), or `all`: true, or `cacheBuild` (a build id, cache key, program key or path, or `all`) | Cancels it (or all of this client's requests), running or still queued; `cacheBuild` cancels background upgrade cache builds, which belong to no client. |
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
| `holders` | `conflict` on `open_project`: every client using the project, each as a `holderInfo`. |
| `project`, `gpr`, `name`, `writable`, `revision` | The project concerned (its revision: see "Revisions and `refresh`"). |
| `program`, `path`, `sha256` | The program concerned: its key, its project path and its executable's SHA-256. |
| `suggest` | What to do: `retry` (a lock that will be released: retry or raise `wait`), `fork_project` (the project or program has another writer, or is a shared read-only view: write your own working copy), `open_read_only` (another process holds the project writable), `open_program writable`. |
| `suggestion` | With `suggest: fork_project`: a ready request, `{"cmd": "fork_project", "project": "p1", "path": "<a folder next to the project>", "writable": true}`. The path is only a proposal. |

## Several clients

- **Projects are shared.** Clients that open the same project (by any path to it) use one
  instance. Different projects never wait on each other.
- **Programs are shared.** Two clients that open the same program use one instance and decompile
  it in parallel with separate pooled decompilers.
- **Each program has a fair read/write lock.** Queries and contained scripts share it. Edits,
  analysis, saves, owner scripts and mode changes hold it alone. A request that cannot get it
  within `wait` fails with `busy`, naming the holder (client, harness, command, how long).
- **One writer per program.** Only the client that opened a program writable may `rename`,
  `comment`, `analyze`, `save` or run a changing script. Others get `not_owner`; they may still
  read it and then see the owner's unsaved changes, as a second tool window would.
- **Fair scheduling.** Requests take a slot in one of two lanes before any lock: **quick**
  (decompile, functions, list, open, rename; one slot per CPU) and **long** (analyze, import,
  script, save; a quarter of the CPUs). Long work can never take the slots quick queries need, so
  one client's whole-program export or analysis does not delay another's 10 ms decompile. When a
  lane is full, waiting requests are admitted round-robin by client, so a client that sends a
  hundred requests cannot starve one that sends one. The daemon's own background work (upgrade
  cache builds) takes a long slot only while no client waits for one. `status` shows each lane's
  use and queue.
- **Cancellation is per client.** `cancel` reaches a client's own requests, running or queued.
- **Leaving is safe.** When a client disconnects or its process dies (the OS resets its socket),
  its requests are cancelled, its unsaved changes are discarded (and logged), and its programs go
  back to read-only for the others. Another client that asks for the program meanwhile waits for
  that release within its `wait`.
- **Opening a project writable is refused while another client uses its read-only view**, and
  the reverse joins: a read-only client in a writable project opens programs read-only.

## Who can do what at the same time

The rules above, as a table. "Same program" means the same file in the same project; a read-only
view and a writable project are described in "Read-only view, writable project".

| Situation | Result | Why |
|---|---|---|
| Any number of readers of one program | in parallel | No project lock; they share one warm program and each decompile takes its own pooled decompiler. Queries hold the program's shared lock. |
| Any number of read-only views of one project (also a Ghidra window) | in parallel | A read-only view takes no project lock and writes nothing. |
| Writers in **different projects** | in parallel | Different projects never wait on each other (the one exception is `import`, below). |
| Two writers of the **same program** | one wins, the other gets `not_owner` | One owner per program: the client that opened it writable. Others may read it and see its unsaved changes. |
| Two writers on **different programs of one writable project** | allowed, but **not independent** | A writable project is one exclusive open (one project lock, held by the daemon). A second client that opens the same project writable joins that one instance (it does not get `conflict`); each program has its own owner, but the clients share the project: closing it waits for the others' running requests, it closes when its last user leaves, and a script with project access can reach every program in it. Give each writer its own working copy instead ("Working copies: `fork_project`"). |
| A second **process** (a Ghidra window, `analyzeHeadless`, another daemon) opens a project this daemon holds writable, or the reverse | `conflict` | The project lock is held by one process; the error names the lock file. |
| `open_project` writable while another client of this daemon uses its read-only view | `conflict` | The read-only view would change under its reader. The reverse joins: a read-only request on a writable project opens programs read-only. Reopen writable when the other readers have left, or `fork_project` the project and write the fork while they keep reading the master. |
| Read-only view of a project another process has open and saves | works, flagged `stale` | It shows the project as it was when the view opened; its clients are told with `stale` on their next answers, and `refresh` reopens the view for all of them at once, without anyone leaving ("Revisions and `refresh`"). |
| Concurrent `import`s | **serialized**, daemon-wide | Ghidra's loaders find libraries through one global "active project", so imports (and upgrade cache builds, which open their copy under it) run one at a time, in any project. Details of waiting and cancelling queued imports: <!-- IMPORT-QUEUE-LANE: replace this comment with the import queue's behaviour (position, holder, cancel of a queued import); do not guess. --> |

What the codes mean when two clients meet:

- **`not_owner`**: the program is open writable by another client of this daemon, and you asked
  for something only its owner may do (`rename`, `comment`, `analyze`, `save`, a changing
  script, or a writable `open_program`). `details.owner` is the owner's client id (the
  `clients` list of `status` names it and its harness). Read it, wait for the owner to save and
  close it, or `fork_project` the project and work in the copy (the error's `suggest` and
  `suggestion` say so).
- **`conflict`**: the project, not a program, cannot be given to you as asked: its lock belongs to
  another process, it is open read-only and in use by others while you asked for writable, the
  session is shutting down, a program needs a database upgrade you did not allow (`"upgrade":
  true`), a name is ambiguous, or a `fork_project` cannot start (the source is being written,
  the destination exists, the copy is larger than allowed: `details.reason`). Nothing is
  waiting: retrying will not help until the situation changes.
- **`busy`**: a slot or a lock did not come free within `wait` (default 10 s). `details` names the
  lane or the program, what wanted it, and the holder (client, harness, command) and for how
  long. Retry, or pass a longer `wait`; nothing was queued past the deadline.

All three carry `holderInfo` and `suggest` in `details` (see "Error codes"): who holds it, and
whether the answer is to retry, to fork, or to open read-only.

## Scripts

`script` runs a GhidraScript the way the window's Script Manager does: `currentProgram`,
`currentAddress`, `state.getProject()`, `getScriptArgs()`, `println`, `monitor`, and
`isRunningHeadless()` true. `HeadlessScript` subclasses also get `storeHeadlessValue` and
`getStoredHeadlessValue`. The session binds them to `HeadlessAnalyzer.getInstance()` through
Ghidra's package-private setter, reflectively, so no Ghidra class is changed.

- On a program **this client owns writable**, the script runs exclusively and its changes stay
  in the program, unsaved unless `"save": true`.
- Otherwise the script is **contained**: it runs inside an outer transaction that is always
  rolled back, so it cannot change what other clients see or what is saved. Contained scripts
  share the program lock and run in parallel, unless `"exclusive": true`. A script that must run
  outside every transaction, such as version tracking, which ends the script's transaction to
  take its own locks, must run as owner.
- With `"program": null`, or with no program open, it runs with only the active project (or
  none).

A script is Java with the session's rights, so this is not a sandbox. Containment protects other
clients' view of the program, not the machine.

`examples/HeadlessApiProbe.java` is a script that exercises, without a window, everything people
usually open the window for: C headers parsed into a `.gdt` and applied, enum, union, typedef and
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
   read-only view: no copy, no lock, the project stays byte-identical). `list` with `sha256` (or
   `programsOnly`) finds the program by hash; `open_program` it and check `info.sha256` before
   trusting answers.
3. **Ask.** `decompile`, `functions`, or `script` for anything else, bounded by `maxChars`. The
   program and its decompilers stay warm for the next client too.
4. **New binary.** `open_project` a working project with `"writable": true`, then `import` with
   `"analyze": true`. The same file is never imported twice.
5. **Change things** (names, types, bulk imports, version tracking) in a writable project that is
   a working copy, never in a master you want unchanged: `fork_project` the master, which other
   clients keep reading meanwhile, and write the fork.
6. **Errors.** `busy`: retry, or raise `wait`. `not_owner`: use your own working copy (the
   answer's `suggestion` is a ready `fork_project` request).
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
  block-cloned where the file system can, and the project stays byte-identical.
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
| Warm `decompile` | 7.0-7.3 ms | 7.1 ms | 6.7-7.1 ms |

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
| Warm `decompile` | 6.3 ms |
| Another harness process, while the first is connected: connect + `hello`, join the project, `open_program` (already open), `decompile` | 14 ms, 0.9 ms, 0.9 ms, 7.4 ms |
| A harness that arrives after everyone left (within `keepWarm`): `open_program` | 1.7 ms (no reopen) |
| 40 decompiles of different functions by one harness | 0.2-1.2 s |
| Heap in use with that program open | 79-327 MB of a 15 GB ceiling |

So a harness pays the cold start once per machine, not once per question or per process; later
clients find projects, programs and decompilers already warm. For comparison, an
`analyzeHeadless -process ... -readOnly -postScript` run doing one decompile on the same project
took 7.0-7.8 s per question and needed a copy of the project.

## Tests

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
  a private stdio session, and the upgrade cache (a current program does not use it; with
  `--legacy-project`, a project saved by an older Ghidra, best a small one, which the test
  block-clones first: an opted-out daemon upgrades in memory; the first open takes in-memory time
  and starts the build; two concurrent opens make one build; after the build a reopen comes from
  the copy and is faster; a daemon killed mid-build leaves no entry and the next start builds
  cleanly; a stop mid-build is prompt; a queued build waits for a client's long job, fails when
  the source changes meanwhile, and the next open retries; `cancel` stops a build; an older key's
  copy is removed; the source stays byte-identical); `holders` (who holds what, in `busy`, `conflict` and
  `not_owner`, and the suggested action); `fork` (a fork while the master's view stays open and
  in use; its sidecar; a fork of a fork; unsaved changes, an existing destination, a source
  another client or process writes, refused; `copy-on-write`, `auto` and `full` modes; the master
  stays byte-identical); `revisions` (revisions in `open_project`, `open_program`, `info` and
  `status`; another process saves: `stale` on the readers' next answers; one reader's `refresh`
  switches both, the other is told once with `refreshed`; a fork starts at its source's revision;
  a writable project needs no refresh); `overlays` (two clients' overlays of one program show
  different names while a third client and the owners' plain view see the canonical program; an
  overlay is private; a failing operation rolls back its whole call; a signature and a data type;
  a killed owner's overlay is dropped and the shared program is untouched; `promote_overlay` into
  a fork; a refresh rebuilds overlays; `drop_overlay`).

```
python examples/session_smoke.py --ghidra <install> --work <empty dir> --binary A.exe --binary B.exe
python examples/daemon_tests.py --ghidra <install> --work <empty dir> --exe A.exe --dll B.dll [--project <analysed project>] [--legacy-project <older project> [--legacy-program <path>]]
python examples/contract_tests.py --ghidra <install> --work <empty dir> [--lines 600000]
```

Both use their own state dir and daemon instance, so they never touch the user's daemon.

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

Two fixes in Ghidra itself, both found by this module's measurements, each a few lines and each
useful to any Ghidra process:

| Where | Before | After |
|---|---|---|
| `Framework/DB`, `LocalBufferFile.close`/`delete` | A temporary buffer file (a program's database cache) is closed, then deleted. On ReFS (a Windows Dev Drive) the last close of a file writes all its dirty cached pages back to disk first, even when the file is deleted right after: closing a large program, or shutting a session down with one open, took 22-41 s with `java.io.tmpdir` there (up to 150 s seen), against 0.05 s on NTFS. | A temporary file is truncated to 0 bytes before it is closed, which drops its unwritten pages: 0.25-0.76 s on the same drive. Nothing reads it again, so nothing else changes. |
| `Framework/SoftwareModeling`, `SleighLanguageFile` | On master, the language service opens a `<language>.sla.lock` file read-write for every language definition (about 300) when it starts, only to learn whether it could lock it. Each open and close of a file on the install's volume costs milliseconds, more on a volume with an antivirus filter: the first `open_program` of a session took 1.4-6.9 s instead of about 0.8 s. | The lock file is created the first time a language actually needs it (`canLock`, `withLock`): one or two per session. Same results, same rules for a directory the user cannot write. |

The distribution also leaves out `__pycache__` folders and `.pyc` files that running a module's
`support/` scripts from the source tree leaves behind (`gradle/distributableGhidraModule.gradle`).

## What is already scriptable (Ghidra master, 12.3 DEV)

| Window feature | API, headless | Verdict |
|---|---|---|
| Version tracking | `VTSessionDB.createVTSession` (`Features/VersionTracking/.../api/db/VTSessionDB.java:116`), `VTProgramCorrelatorFactory.createCorrelator` (`.../api/main/VTProgramCorrelatorFactory.java:68`), `AutoVersionTrackingTask(VTSession, ToolOptions)` (`.../gui/actions/AutoVersionTrackingTask.java:96`; runs with default options and needs no tool); `ghidra_scripts/AutoVersionTrackingScript.java` already branches on `isRunningHeadless()` | Script. What headless lacks is two programs open in one long-lived process; the session supplies that. |
| Bulk types | `CParserUtils.parseHeaderFiles` (`Features/Base/.../cparser/C/CParserUtils.java:402`, returning a `FileDataTypeArchive`; the `FileDataTypeManager` variants are deprecated since 12.3), `DataTypeArchiveFactory.createFileArchive` / `openReadOnly` / `openForUpdate` (`Framework/SoftwareModeling/.../database/dtarchive/DataTypeArchiveFactory.java:49,121,160`), `DataTypeManager.addDataType` / `addDataTypes` (`.../data/DataTypeManager.java:133,147`); `EnumDataType`, `UnionDataType`, `TypedefDataType`, `FunctionDefinitionDataType` | Script. |
| Auto create structure | `FillOutStructureCmd(ProgramLocation, DecompileOptions)` (`Features/Decompiler/.../util/FillOutStructureCmd.java:56`) takes a `VariableLocation` or `FunctionParameterFieldLocation`, not only a decompiler click; `FillOutStructureHelper.processStructure` (`FillOutStructureHelper.java:106`) | Script. |
| Re-analysis | `AutoAnalysisManager.getAnalysisManager`, `reAnalyzeAll(AddressSetView)`, `startAnalysis(TaskMonitor)` (`Features/Base/.../analysis/AutoAnalysisManager.java:948,325,604`; it runs in the calling thread when there is no tool) | API, and the `analyze` command. |
| Data labels, global renames, bookmarks | `SymbolTable.createLabel`, `Symbol.setName` / `setNameAndNamespace`, `DataUtilities.createData`, `BookmarkManager.setBookmark` | API, and the `rename` command. |
| Several programs and projects, switching, checkout, save | `Project`, `ProjectData.getFile`, `DomainFolder.getFiles`, `DomainFile.getDomainObject` / `getReadOnlyDomainObject` / `checkout` / `save` | The API exists. `analyzeHeadless` exposes one program per run and always takes the project lock. **This is the part that needed new code: this module.** |

## Limits

- Tested on Windows 11 only. The launcher and module have no Windows-specific path (POSIX file
  locks, `start_new_session`, owner-only state dir), but Linux and macOS have not been run.
- The AOT cache needs JDK 25 or later (`-XX:AOTCacheOutput`); older JDKs run without it.
- A read-only view does not pick up changes saved to the project by another process after it was
  opened until a client sends `refresh` (its clients are told with `stale`).
- With `tmpdir` on a ReFS volume (a Windows Dev Drive), writing Ghidra's buffer cache is slower
  than on NTFS (ReFS writes a file's dirty pages back when its last handle closes), so an
  in-memory upgrade or a large analysis is slower there. Closing is fixed (see "Changes outside
  this module"); put `tmpdir` on a fast NTFS or ext4 disk with room if you can.
- Imports run one at a time across the daemon: Ghidra's loaders find libraries through one global
  "active project".
