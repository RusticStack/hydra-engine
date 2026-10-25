# Headless Session

`analyzeHeadless` is a command about one program file: it opens (and locks) one project, runs
pre/post scripts against the programs that `-process`/`-import` select, and exits. The Ghidra
window is a session: you open a project, see what is in it, pick a program, switch to another,
keep working, save, and the process stays.

`headlessSession` is that session without the window. It is one long-lived JVM, driven by JSON
lines over stdio and/or an authenticated loopback socket, that can:

- open an existing project by its `.gpr`, its folder, or a parent folder with one project below;
- list folders and programs (with each program's SHA-256 and language, without opening it);
- open and switch the active program **without importing**, read-only by default, writable on
  request, with save and close;
- import a new program into the open project (never twice: a file already in the project by
  SHA-256 is reported, not re-imported);
- run auto-analysis on demand;
- run any GhidraScript (Java, or Python through a script provider) against the active program,
  with arguments, and return what it printed;
- serve several clients at once with per-program locking and ownership;
- stay alive for the next command.

It is a new module and two launch scripts. No existing Ghidra class is changed.

## Starting it

```
support/headlessSession[.bat] [-project <file.gpr | dir>] [-writable]
                              [-listen [127.0.0.1:]<port>] [-endpoint <file>] [-noStdio]
                              [-idleTimeout <seconds>] [-scriptPath <dir>]... [-log <file>]
```

| Option | Meaning |
|---|---|
| `-project` | Open this project at start. A `.gpr`, the folder holding it, a `.rep`, or a parent folder with exactly one project at most two levels below. |
| `-writable` | Open it writable. This takes the project lock, as the window's *Open Project* does. Default: a read-only view (below). |
| `-listen` | Also serve socket clients on this loopback port (`0` picks a free one). Non-loopback addresses are refused. |
| `-endpoint` | Write `{protocol, pid, host, port, token, project, ...}` to this file for socket clients. The file is created owner-only on POSIX and removed at exit. |
| `-noStdio` | Daemon: do not serve stdin/stdout. Needs `-listen`. |
| `-idleTimeout` | With `-noStdio`: stop after this many seconds with no client connected. |
| `-scriptPath` | An extra GhidraScript directory. Repeat it for several. A `;`-separated list also works when quoted; on Windows `cmd` splits an unquoted `;`. |
| `-log` | Ghidra's application log file. |

`GHIDRA_HEADLESS_MAXMEM`, `GHIDRA_JAVA_OPTIONS` and `GHIDRA_HEADLESS_JAVA_OPTIONS` work as for
`analyzeHeadless`. Ghidra keeps unsaved database changes in `java.io.tmpdir`. To keep a large
program's temporary files off the system drive, pass `-Djava.io.tmpdir=<dir>` in
`GHIDRA_HEADLESS_JAVA_OPTIONS`.

stdout belongs to the protocol. Ghidra's log and anything a script writes to `System.out` go to
stderr. The Windows launcher also keeps `launch.bat` from pausing (and so from printing to stdout
and reading stdin) when the session is started by another program through `cmd /c`.

## Read-only view, writable project

By default the project is opened the way the window's *File > View Project* opens a project: as
`new DefaultProjectData(locator, false, false)`, which takes **no project lock** and opens every
file system read-only. Nothing in the project is written: not a lock file, not an index, not a
timestamp. Any number of sessions, and a Ghidra window, can read the same project at the same
time, and there is no need to copy the project first.

`analyzeHeadless` cannot do this. It always opens the project through `DefaultProject`, which
calls `new DefaultProjectData(locator, true, ...)` and locks the project, even with `-readOnly`;
`-readOnly` only skips the save (`HeadlessAnalyzer.openProject` and its `HeadlessProject`;
`processFileNoImport` opens the program with `getDomainObject` and does not save it;
`DefaultProject.java:119`).

With `-writable` (or `open_project` `"writable": true`) the project is opened with its lock. Only
one process can hold it. A second writable open gets `conflict` with the lock file's path.

## Protocol (version 1)

One JSON object per line, UTF-8, `\n`-terminated, at most 64 MiB per line.

Request:

```json
{"id": 7, "cmd": "decompile", "address": "0x1405d53a0", "wait": 10000}
```

`id` is any JSON value; the response echoes it. `cmd` is the command. Every command also accepts
`wait`, the milliseconds it may wait for a lock before failing with `busy` (default 10000).

Response:

```json
{"id": 7, "ok": true, "result": {...}, "ms": 12}
{"id": 7, "ok": false, "error": {"code": "busy", "message": "...", "details": {...}}, "ms": 500}
```

Events carry no `ok`. The first line on stdio is `ready` (or `fatal`, and then the process exits
with code 2). Long commands send throttled `progress` events with the request's `id`:

```json
{"event": "ready", "protocol": 1, "ghidra": "12.1.4", "pid": 1234, "project": {...}, "listen": {...}, "startupMs": 1363}
{"event": "progress", "id": 9, "message": "Analyzing...", "progress": 120, "maximum": 400}
```

Requests from one client run in the order sent. `ping`, `status` and `cancel` are answered at
once, even while that client's previous request is still running. Different clients run in
parallel.

### Commands

| `cmd` | Fields | Does |
|---|---|---|
| `hello` | `client`, `harness`, `token` (socket) | Names the client. On a socket it must be the first request, with the endpoint's `token`. |
| `ping` | | `{"pong": true}` |
| `status` | | Session, project, open programs (mode, owner, users, what holds each lock), clients and their running requests. |
| `open_project` | `path`, `writable`=false, `discard`=false | Opens a project. Asking for the open one is a no-op. Switching or upgrading to writable is allowed only when no other client uses a program, and only with `discard` if something is unsaved, as the window does when it changes project. |
| `close_project` | `discard`=false | Same rules. |
| `project` | | The open project. |
| `list` | `folder`="/", `recursive`=true, `programsOnly`=false, `metadata`=true, `offset`, `limit`=1000 | Folders and files, with `sha256`, `language`, `executable` and `open` (who uses it) for programs. Paged, with `truncated`. |
| `open_program` / `switch` | `path`, `writable`=false, `checkout`=false, `upgrade`=false | Opens the program, or joins it if another client has it open, and makes it this client's active program. `path` is a project path (`/folder/name`) or a name that is unique in the project. Writable needs a writable project; a versioned file needs `checkout`. Switching back to a program already open costs nothing. |
| `programs` | | This client's open programs and its active one. |
| `info` | `program`? | The program: language, compiler, image base, format, executable path, SHA-256, MD5, function count, analysed, changed, mode, owner, users. |
| `close_program` | `program`?, `discard`=false | Drops this client's use. The owner of a changed program must `save` first or pass `discard`. |
| `functions` | `program`?, `contains`, `regex`, `offset`, `limit`=200 (max 10000) | Functions by name filter, paged. |
| `decompile` | `program`?, `address` or `name`, `timeout`=60 s, `maxChars`=200000 | C text and signature. Decompilers are pooled per program, so warm calls skip the start-up cost. |
| `rename` | `program`?, `address`, `name`, `kind`=auto\|function\|label | Renames the function at the address, or creates or renames the primary label there: data labels and global names. Owner only. |
| `comment` | `program`?, `address`, `text` (null clears), `type`=eol\|pre\|post\|plate\|repeatable | Owner only. |
| `analyze` | `program`?, `options` {name: value}, `ranges` [[start, end], ...], `timeout` s | Sets analysis options, then runs auto-analysis on everything (or what the ranges trigger) in this thread, the same sequence `analyzeHeadless` uses, and marks the program analysed. Owner only. |
| `save` | `program`?, `comment` | Owner only. |
| `import` | `file`, `folder`="/", `name`, `language`, `compiler`, `analyze`=false, `duplicate`=false, `timeout` | Imports into the writable project with `ProgramLoader`, saves it, opens it writable for this client and optionally analyses and saves it. A file whose SHA-256 is already in the project returns `{"imported": false, "existing": [...]}` unless `duplicate`. |
| `script` | `script` (name on the script path, or a file path), `args` [...], `program`? (null: none), `address`, `exclusive`=false, `save`=false, `timeout` s, `maxChars` | Runs a GhidraScript with this program as `currentProgram` (and `address` as `currentAddress`), and returns its `println` output. See "Scripts" below. |
| `cancel` | `target` (an id of this client's running request) | Cancels it through its task monitor. |
| `shutdown` | `force`=false | Stops the session. Unsaved changes are discarded. From a socket client it is refused while other clients are connected, unless `force`. |

`program`? means: the client's active program unless a `program` path is given.

Addresses are `0x140001000`, `va:0x140001000`, `rva:0x1000` (from the image base) or
`space:offset`. Results print addresses as `0x...` in the default space.

### Error codes

`bad_request`, `unknown_command`, `unauthorized`, `no_project`, `no_program`, `not_found`,
`read_only`, `not_owner`, `busy` (with `holder` and `heldMs`), `conflict`, `unsaved_changes`,
`cancelled` (also on `timeout`), `failed` (Ghidra's message, plus a short `trace`).

## Several clients

There is one session process per project, and every client of that project talks to it, over
stdio (the launcher) or the socket (anyone holding the endpoint's token). That process is the
only one that holds the project lock in writable mode. In read-only mode, other processes can open
their own read-only view of the same project at the same time.

Inside the session:

- **Programs are shared.** Two clients that open the same program use one instance, and decompile
  it in parallel with separate pooled decompilers.
- **Each program has a fair read/write lock.** Queries and contained scripts share it. Edits,
  analysis, saves, owner scripts and mode changes hold it exclusively. Work on different programs
  never waits on each other. A request that cannot get its lock within `wait` fails with `busy`,
  naming the holder, instead of queueing forever.
- **One writer per program.** A writable program has exactly one owner, the client that opened it
  writable. Only the owner may `rename`, `comment`, `analyze`, `save` or run a changing script.
  Other clients get `not_owner`. They may still read it, and then see the owner's unsaved changes,
  as a second tool window would.
- **Leaving is safe.** When the owner closes its program or disconnects, unsaved changes are
  discarded (and logged), and the program goes back to read-only for its remaining users. A
  disconnect also cancels that client's running requests.
- **The project is locked for open/close.** Every command holds the project read lock. Opening,
  switching and closing the project need it exclusively, and are refused while another client
  uses a program.

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
- With `"program": null`, or with no program open, it runs with only the project.

A script is Java with the session's rights, so this is not a sandbox. Containment protects other
clients' view of the program, not the machine.

`examples/HeadlessApiProbe.java` is a script that exercises, without a window, everything people
usually open the window for: C headers parsed into a `.gdt` and applied, enum, union, typedef and
function-definition types, typed data with a global label, a global rename, a bookmark, auto
create structure from usage, and version tracking from another program in the project.

## Why each part lives where it does

| Part | Where | Why |
|---|---|---|
| Version tracking, bulk types, structure from usage, re-analysis, labels | Ghidra's public Java API, called from a script | Already there and already headless; see the verdict table below. Nothing to fork. |
| Session process, project and program registry, locking, transports | This module (`Features/HeadlessSession`) | It has to live in a JVM that has Ghidra initialised and holds the open `Project` and `Program` objects across requests. A launcher outside Ghidra can only start `analyzeHeadless`, which opens one project, processes and exits. |
| Read-only project view | This module | `DefaultProjectData`'s read-only constructor is public, but `analyzeHeadless` never uses it. Using it needs a `DefaultProject` subclass (`SessionProject`), which is module code. No core change. |
| `support/headlessSession[.bat]` | `RuntimeScripts` | Same JVM settings and classpath as `analyzeHeadless`, through `launch.bat`/`launch.sh`. |
| Anything specific to one client (an MCP server's tools, its own stores and checks) | That client | The session is a generic Ghidra front end. Clients call it; they do not contain it, and it does not contain them. |

The module needs nothing private from Ghidra. It could ship as an extension, but it is a module so
that the launch scripts and the build ship it with every distribution, the same as
`analyzeHeadless`.

## What is already scriptable (Ghidra 12.1.4)

| Window feature | API, headless | Verdict |
|---|---|---|
| Version tracking | `VTSessionDB.createVTSession` (`Features/VersionTracking/.../api/db/VTSessionDB.java:114`), `VTProgramCorrelatorFactory.createCorrelator` (`.../api/main/VTProgramCorrelatorFactory.java:68`), `AutoVersionTrackingTask(VTSession, ToolOptions)` (`.../gui/actions/AutoVersionTrackingTask.java:96`; runs with default options and needs no tool); `ghidra_scripts/AutoVersionTrackingScript.java` already branches on `isRunningHeadless()` | Script. What headless lacks is two programs open in one long-lived process; the session supplies that. |
| Bulk types | `CParserUtils.parseHeaderFiles` (`Features/Base/.../cparser/C/CParserUtils.java:273`), `FileDataTypeManager.createFileArchive` / `openFileArchive` (`Framework/SoftwareModeling/.../data/FileDataTypeManager.java:97,194`), `DataTypeManager.addDataType` / `addDataTypes` (`.../data/DataTypeManager.java:123,137`); `EnumDataType`, `UnionDataType`, `TypedefDataType`, `FunctionDefinitionDataType` | Script. |
| Auto create structure | `FillOutStructureCmd(ProgramLocation, DecompileOptions)` (`Features/Decompiler/.../util/FillOutStructureCmd.java:56`) takes a `VariableLocation` or `FunctionParameterFieldLocation`, not only a decompiler click; `FillOutStructureHelper.processStructure` (`FillOutStructureHelper.java:106`) | Script. |
| Re-analysis | `AutoAnalysisManager.getAnalysisManager`, `reAnalyzeAll(AddressSetView)`, `startAnalysis(TaskMonitor)` (`Features/Base/.../analysis/AutoAnalysisManager.java:949,324,603`; it runs in the calling thread when there is no tool) | API, and the `analyze` command. |
| Data labels, global renames, bookmarks | `SymbolTable.createLabel`, `Symbol.setName` / `setNameAndNamespace`, `DataUtilities.createData`, `BookmarkManager.setBookmark` | API, and the `rename` command. |
| Several programs, switching, checkout, save | `Project`, `ProjectData.getFile`, `DomainFolder.getFiles`, `DomainFile.getDomainObject` / `getReadOnlyDomainObject` / `checkout` / `save` | The API exists. `analyzeHeadless` exposes one program per run and always takes the project lock. **This is the part that needed new code: this module.** |

## How a client (for example an MCP server) should use it

1. Find or start the session for a project. Keep an endpoint file per project, for example
   `<state dir>/sessions/<sha256 of the .gpr path>.json`. If it exists and `ping` answers, join;
   otherwise start `headlessSession -project <gpr> -listen 0 -endpoint <that file> -noStdio
   -idleTimeout 900` and wait for the file.
2. `hello` with the token, your client name and harness.
3. `list` (`programsOnly`), then `open_program` the one whose `sha256` you expect. Check `info`'s
   `sha256` before trusting answers.
4. Ask: `decompile`, `functions`, or `script` for anything else. Keep scripts bounded; they return
   what they print, up to `maxChars`.
5. To change things, use a writable session on a working copy of the project, `open_program`
   with `writable`, edit, `save`. Never on a master project you want unchanged.
6. On `busy`, retry with a longer `wait`, or ask another program. On `not_owner`, work on your own
   copy.

`examples/session_client.py` is a standard-library Python client for both transports.
