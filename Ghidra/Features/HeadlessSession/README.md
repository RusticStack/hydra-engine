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

It is one new module. No existing Ghidra class or launcher is changed, and there are no `.bat`,
`.sh` or PowerShell launchers: `support/ghidra_session.py` (Python 3.10+, standard library only,
any OS) starts the JVM itself.

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
  size and time, so an update or another JDK just runs without it until you rebuild it.

| Command | Does |
|---|---|
| `ensure` | Starts the daemon if it is not running; prints its endpoint (without the token). |
| `status` | The running daemon: projects, programs and who uses them, clients, scheduler, memory, launch info. |
| `call CMD key=value...` | One request through the daemon; values are JSON when they parse (`writable=true`). |
| `stop [--force]` | Asks the daemon to shut down (refused while other clients are connected, unless `--force`). |
| `kill` | Kills the daemon's JVM without a shutdown (wedged daemon, tests). |
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

A read-only view does not see changes another process saves to the project after it was opened.
Reopen it (all clients leave it, or wait for `keepWarm`) to see them.

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
| `hello` | `client`, `harness`, `token` (socket) | Names the client. On a socket it must be the first request, with the endpoint's `token`. |
| `ping` | | `{"pong": true}` |
| `status` | | Session, launch info, memory, projects, programs (mode, owner, users, what holds each lock, idle time), clients and their requests, scheduler lanes. |
| `projects` | | Open projects, which ones this client joined, its active project. |
| `open_project` | `path`, `writable`=false, `discard`=false | Joins the project, opening it if needed. `path` is a `.gpr`, its folder, a `.rep`, or a parent folder with exactly one project at most two levels below. A read-only view is reopened writable only when no other client uses it; a read-only request on a writable project joins it. |
| `close_project` | `project`?, `discard`=false | Leaves the project (closes this client's programs there). A writable project closes when its last user leaves; a read-only one after `keepWarm`. |
| `project` | `project`? | The project: id, name, paths, writable, files, users, programs. |
| `list` | `project`?, `folder`="/", `recursive`=true, `programsOnly`=false, `metadata`=true, `sha256`, `offset`, `limit`=1000 | Folders and files, with `key`, `sha256`, `language`, `format`, `executable` and `open` (who uses it) for programs; `sha256` finds a program by its hash. Paged, with `truncated`. |
| `open_program` / `switch` | `path` (path, unique name or key), `project`?, `writable`=false, `checkout`=false, `upgrade`=false | Opens the program, or joins it if it is open (also a warm one nobody uses), and makes it active. Writable needs a writable project; a versioned file needs `checkout`. |
| `programs` | | This client's programs (all projects) and its active ones. |
| `info` | `program`? | Key, language, compiler, image base, format, executable path, SHA-256, MD5, functions, analysed, changed, mode, owner, users. |
| `close_program` | `program`?, `discard`=false | Drops this client's use. The owner of a changed program must `save` first or pass `discard`. |
| `functions` | `program`?, `contains`, `regex`, `offset`, `limit`=200 (max 10000) | Functions by name filter, paged. |
| `decompile` | `program`?, `address` or `name`, `timeout`=60 s, `maxChars`=200000 | C text and signature. Decompilers are pooled per program, so warm calls skip the start-up cost. |
| `rename` | `program`?, `address`, `name`, `kind`=auto\|function\|label | Renames the function at the address, or creates or renames the primary label: data labels and global names. Owner only. |
| `comment` | `program`?, `address`, `text` (null clears), `type`=eol\|pre\|post\|plate\|repeatable | Owner only. |
| `analyze` | `program`?, `options` {name: value}, `ranges` [[start, end], ...], `timeout` s | Sets analysis options, then runs auto-analysis on everything (or what the ranges trigger) the way `analyzeHeadless` does, and marks the program analysed. Owner only. |
| `save` | `program`?, `comment` | Owner only. |
| `import` | `file`, `project`?, `folder`="/", `name`, `language`, `compiler`, `analyze`=false, `duplicate`=false, `timeout` | Imports into a writable project with `ProgramLoader` (any format it accepts), saves it, opens it writable for this client, and optionally analyses and saves it. A file whose SHA-256 is already in the project returns `{"imported": false, "existing": [...]}` unless `duplicate`. |
| `script` | `script` (name on the script path, or a file path), `args` [...], `program`? (null: none), `project`?, `address`, `exclusive`=false, `save`=false, `timeout` s, `maxChars` | Runs a GhidraScript and returns its `println` output. See "Scripts". |
| `cancel` | `target` (an id of this client's request), or `all`: true | Cancels it (or all of this client's requests), running or still queued. |
| `shutdown` | `force`=false | Stops the session; unsaved changes are discarded. From a socket client it is refused while other clients are connected, unless `force`. |

Addresses are `0x140001000`, `va:0x140001000`, `rva:0x1000` (from the image base) or
`space:offset`. Results print addresses as `0x...` in the default space.

### Error codes

`bad_request`, `unknown_command`, `unauthorized`, `no_project`, `no_program`, `not_found`,
`read_only`, `not_owner`, `busy` (with what holds the slot or lock and for how long), `conflict`,
`unsaved_changes`, `cancelled` (also on `timeout`), `failed` (Ghidra's message, plus a short
`trace`).

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
  hundred requests cannot starve one that sends one. `status` shows each lane's use and queue.
- **Cancellation is per client.** `cancel` reaches a client's own requests, running or queued.
- **Leaving is safe.** When a client disconnects or its process dies (the OS resets its socket),
  its requests are cancelled, its unsaved changes are discarded (and logged), and its programs go
  back to read-only for the others. Another client that asks for the program meanwhile waits for
  that release within its `wait`.
- **Opening a project writable is refused while another client uses its read-only view**, and
  the reverse joins: a read-only client in a writable project opens programs read-only.

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
   a working copy, never in a master you want unchanged; another client can keep a read-only view
   of the master open at the same time.
6. **Errors.** `busy`: retry, or raise `wait`. `not_owner`: use your own working copy.
   `unsaved_changes`: `save`, or close with `discard`.

## Performance

### Ghidra master (12.3 DEV) against 12.1.4, same machine, same day

Windows 11, JDK 25.0.4, 16-core i7-13700KF, 64 GB, Dev Drive (ReFS); fast mode, AOT cache and
class search cache on; the same 66.7 MB x64 executable with 243,855 functions, opened read-only,
each build from a project in its own database format. Medians of 7 runs (35 for warm decompiles);
the ranges are min-max.

| | 12.1.4 | master |
|---|---|---|
| Launch until `ready` | 389 ms (378-585) | 482 ms (469-503) |
| `open_program` (243,855 functions) | 784 ms (752-1402) | 1445 ms (1114-1902) |
| First `decompile` | 254 ms | 250 ms |
| **Launch until the first answer** | **1502 ms** (1448-2117) | **2279 ms** (1918-2692) |
| Daemon: start it and connect | 493 ms (466-554) | 596 ms (552-726) |
| Daemon: first client's `open_program` | 763 ms (741-803) | 1201 ms (1036-1858) |
| Another client: connect + `hello`, join the project, `open_program` (already open), `decompile` | 16 ms, 0.9 ms, 0.5 ms, 5.5 ms | 11 ms, 0.9 ms, 0.5 ms, 5.5 ms |
| Warm `decompile` | 6.3-6.5 ms | 6.5-6.6 ms |

A project saved by 12.1.4 opens read-only on master without being changed, but every read-only
open upgrades the program in memory first: `open_program` then took 21-24 s for this program
instead of about 1.4 s. Opening it writable is refused until the request passes `"upgrade": true`
(the upgrade is one-way; older Ghidra versions cannot open the result). Use a copy of an older
project, upgrade it once, and open that.

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
- `examples/daemon_tests.py`: two harness processes starting the daemon at once, several
  projects in one daemon, a DLL import, a client killed while it owns a program and analyses it,
  the daemon killed and restarted, fair scheduling, `cancel all`, idle shutdown, warm programs,
  and a private stdio session.

```
python examples/session_smoke.py --ghidra <install> --work <empty dir> --binary A.exe --binary B.exe
python examples/daemon_tests.py --ghidra <install> --work <empty dir> --exe A.exe --dll B.dll [--project <analysed project>]
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

The module needs nothing private from Ghidra beyond the two reflective touches named above
(`HeadlessScript.setHeadlessInstance`, `ClassSearcher`'s search result), each optional.

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
  opened (see above).
- On master, with `tmpdir` on a ReFS Dev Drive, shutting the daemon down after a large program
  was opened from an older project took 60-150 s: Ghidra's `ProgramDB.close` waits in
  `File.delete` of its buffer cache file. With the default temporary directory it took 0.6 s.
  The cause is not isolated yet; until it is, leave `tmpdir` at its default on such a drive, or
  give `stop` a longer timeout.
- Imports run one at a time across the daemon: Ghidra's loaders find libraries through one global
  "active project".
