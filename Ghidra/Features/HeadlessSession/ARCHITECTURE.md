# Headless Session: how the code is organised

This is for people changing the session's Java. How to *use* the session (protocol, commands,
error codes) is in [README.md](README.md). All Java is in one package,
`ghidra.app.util.headless.session`, under `src/main/java`.

## The request path

```
client --JSON line--> Connection --> Session.execute(client, cmd, req, monitor)
                                        |  inline: ping, cancel, status   (answered on the reader thread)
                                        |  Scheduler slot (import queues for ImportGate instead)
                                        v
                                     a command class (table below) --> reply JsonElement
Connection wraps the result as {"id", "ok", "result"|"error", "ms"} and adds the "stale" and
"refreshed" markers (Session.annotate).
```

`Session` keeps the state that is shared by every command (the project maps, the clients, the
scheduler, the upgrade cache, the shutdown flag), the client life cycle (`connect`, `disconnect`,
`close`, `reap`), the session-level commands (`hello`, `status`, `cancel`, `shutdown`, `projects`),
and the dispatch: one `switch` in `Session.execute` that calls a command class. Nothing else
lives there.

Lock order, always (see the class comment of `Session`): a scheduler slot, then
`Session.registry` (only to open, upgrade or close a project), then one `ProjectEntry.lock`, then
one `ProgramEntry.lock`. `Access.lockProject` and `ProgramEntry.acquire` are the only places that
take the last two, and they name the holder in `busy` answers.

## The command classes

| Class | Commands and what else it owns |
|---|---|
| `Session` | state, clients, `hello`, `status`, `cancel`, `shutdown`, `projects`, `annotate`, the dispatch |
| `Access` | not a command: project and program lookup from a request (`projectFor`, `selected`), the locks (`inProject`, `withProgram`, `lockProject`), the ownership checks (`requireOwner`, `notOwner`), the fork suggestion in errors |
| `ProjectCommands` | `open_project`, `close_project`, `refresh`/`reopen`, `list`; writable-in-place reopen, view swap, leave and close |
| `ForkCommands` | `fork_project` |
| `ProgramCommands` | `open_program`/`switch`, `close_program`, `programs`, `info`; the program entry life cycle: read-only, writable and shared opens, upgrade cache copies, release and disposal |
| `QueryCommands` | `functions`, `decompile` |
| `EditCommands` | `edit`, `journal`, `discard_edits`, `save`, `analyze`; journalling of `rename` and `comment`; naming the last editor in a `changed` conflict |
| `Operations` | the changes themselves (`rename`, `label`, `comment`, `signature`, `data_type`), applied all or none; used by edits, overlays and promotion |
| `OverlayCommands` | `overlays`, `apply_overlay`, `drop_overlay`, `promote_overlay`, and every overlay-scoped form of `open_program`, `info`, `functions`, `decompile`, `rename`, `comment`, `script`; the overlays map |
| `ImportCommands` | `import`; the same-file in-flight bookkeeping |
| `ScriptCommands` | `script`; script lookup and the `HeadlessScript` binding |
| `Requests`, `Addresses` | static helpers: `wait`, text caps and the cancelled error; address parsing and printing |

The classes that hold the session's objects are unchanged and are not command classes:
`ProjectEntry`, `ProgramEntry`, `Overlay`, `Client`, `Journal`, `Scheduler`, `ImportGate`,
`UpgradeCache`, `Revision`, `ProjectFork`, `ProjectLocks`, `ProjectResolver`, `Connection`.

Classes added for protocol 3 (hydra.4). None is a command class; each is the one place for its concern, and
the package that owns it registers into it from its own files, so no class below needs an edit to `Session`:

| Class | What it holds |
|---|---|
| `Advertised` | the capability, limit and policy names that `hello` and `status` report, declared in reply order; a package enables its own name, and a name nobody enables is absent from the reply |
| `Settings` | the `-set key=value` flags (the `engine` object of `config.json`); each reader names its key and default, and a value of the wrong type fails at start-up |
| `Identity`, `DbVersions` | the identity block of `hello` (`paths`, `platform`, `analysisIdentity`) and the database format versions in one place; read-only |
| `Preflight` | validation of a request before it queues, registered per command (`fork_project`, `script`) and run by `Scheduler` for a protocol 3 request |
| `Waits` | the one request-bound lock wait: a single timed `tryLock` that `cancel`, a `timeout`, a dead client or a stalled socket can end |
| `WaitStats` | counts the lock waits that had to queue behind another client (`foreignBlocked`), for the tests that assert "no client blocks another" |
| `ProjectRegistry` | the life cycle of each open project as its own state (`OPENING`, `OPEN`, `CLOSING`), so one project's open, join and close never waits on another's |
| `Seals`, `ProjectBackup`, `ProjectFormat` | the sealed predicate (the union of the registry record, `SEALED.json` and the sidecars) and `seal_project`; the backup manifest and its canonical form; the per-project database-format block read without opening a program |
| `ForkIntent`, `ForkSweeper` | the intent record in a fork's staging folder, the admission of `fork_project` publishers (`fork_in_progress`, `exists`) and the lazy sweeper of what a dead publisher left |
| `PrivateInstance` | a throwaway program object opened from the stored file, shared by overlays and by `script` with `isolation:"private"` |

Conventions:

- A command class is `final`, package-private, and is constructed with the `Session` it works
  for (`new ProgramCommands(this)` in `Session`). It reaches another command through the session
  (`s.access`, `s.programCmds`, ...) and the shared state through `s` (`s.projectsById`,
  `s.upgradeCache`, ...). The command classes do not hold state that other classes need, except
  the two maps that belong to a single area (`OverlayCommands.overlays`,
  `ImportCommands.importsInFlight`).
- Static helpers are imported statically (`import static ...Access.lockProject;`), so a call
  reads the same wherever it is made.
- Log lines use `Msg.info(s, ...)`, so they keep the logger name `Session`.
- A command method has the shape `JsonElement name(Client c, JsonObject req[, RequestMonitor m])`
  and throws `SessionException` with one of its codes for every refusal.

## Adding a command

1. Pick the class of its area (or add one with the same shape: `final class X { private final
   Session s; X(Session s) {...} }`, plus a field in `Session`).
2. Write the method. Reach the project with `s.access.projectFor(c, req)` and run under its lock
   with `s.access.inProject(...)`; reach a program with `s.access.withProgram(c, req, cmd,
   exclusive, needOwner, e -> ...)`, which selects it, takes the locks, checks ownership and turns
   exceptions into protocol errors. Read optional fields with `Json.str/bool/num` (they refuse a
   wrong type with `bad_request`) and `Requests.waitMs(req)`.
3. Add its `case` to the `switch` in `Session.execute`. If it must be answered while another
   request runs, add it to `Session.isInline`; if it also has an overlay form, add it to
   `OverlayCommands.overlayScoped` and handle it in `overlayCommand`.
4. A new command or a new reply field is a protocol change: document it in the README
   ("Commands", "Error codes"), and follow its rules for `protocol` and `minClient`.
5. Add its requests to a scenario of `examples/characterization_tests.py`, record, and read the
   diff of the golden files: it must contain only the new steps (see below).
6. If it is about concurrency, add a test to `examples/daemon_tests.py`.

## Characterization: what makes a refactoring safe here

The Java has no unit tests; the tests are Python scripts that drive a real daemon. For a change
that must not alter behaviour, `examples/characterization_tests.py` is the contract: it plays
seven scenarios (`session`, `readonly`, `edits`, `clients`, `fork_refresh`, `overlays`,
`import_script`; 317 requests) against a fresh daemon each and compares every reply, whole
and in the order the daemon wrote its keys, with the golden files in
`examples/characterization/`. Only what differs between two runs of the same build is masked
(timings, pids, ports, paths as `<WORK>` and `<INSTALL>`, file-system dependent copy figures, and
revision fingerprints, renumbered by first appearance). The fixture is two tiny PE files the
script writes itself, so nothing depends on the machine's Windows version and the golden files
contain nothing derived from any real program.

Procedure for a behaviour-preserving change:

1. On the unmodified tree, build, then record (or check that the committed goldens verify):
   `python examples/characterization_tests.py --ghidra <install> --work <empty dir> --record`
2. Make the change, build, and run it without `--record` on the new install. Every scenario must
   report `identical`. A difference prints a unified diff and leaves the actual replies in
   `<work>/actual/<scenario>.json`.
3. Also run `session_smoke.py`, `contract_tests.py` and `daemon_tests.py` (they test what the
   characterization cannot: timing, scheduling, kills, restarts, the upgrade cache).

Procedure for a deliberate change of a reply: change the code, run without `--record`, check that
the diff is exactly what you meant, then `--record` and commit the golden files with the change.

What the characterization does not cover, and why:

| Not covered | Why |
|---|---|
| `fork_project` with `mode` `copy-on-write` or a small `maxCopyMb` | The answer depends on the file system (block clone on ReFS, a refusal or a full copy on NTFS); `daemon_tests.py` `fork` checks it per file system. The `method`, `cloned` and `clonedBy` fields of the other fork replies are masked for the same reason. |
| `busy` on a project lock | Needs a request that holds a project exclusively for a known time; `daemon_tests.py` `holders` and `multi_writer` cover it. (`busy` on a program lock and `conflict`/`not_owner` naming the holder are covered.) |
| Older-format projects, the upgrade cache build (`cacheBuild`, `wait: true`, `legacy_overlay`) | Need a project saved by an older Ghidra and depend on build timing; in `daemon_tests.py` with `--legacy-project`. |
| Progress events, the start-up banner, the endpoint file, `unauthorized` | Not replies to a request; `contract_tests.py` checks the endpoint and the hello contract. |
| The parallel and stdio transports, `maxImports` queueing, kills and restarts | Timing and process behaviour; `daemon_tests.py`. |
| The values of timings, pids, ports, memory and the revision hashes | Differ on every run; masked. Their presence and key order are still checked. |

## The native decompiler between functions

`DecompInterface.decompileFunction` ends every function with `flushNative`, which drops everything the
decompile process fetched from the program: symbols, functions, comments, constant pool, and also every
data-type and string decoding, so the next function fetches its data-types again through callbacks.

* `-Dhydra.decompiler.keepTypes=true` (off by default): while the program's modification number is
  unchanged, a function ends with `flushFunctions` instead (ghidra_process.cc), which clears the same
  symbol, function, comment and constant-pool state but keeps the data-types and string decodings, and the
  Java side keeps its temporary data-type ids for them. A changed modification number, a debug dump, any
  option or action change (`setOptions`, `setSimplificationStyle`, the `toggle*` methods,
  `setSignatureSettings`), `structureGraph`, opening or closing a program and a process restart all go
  back to a full `flushNative`. Function state is never kept: a kept `Funcdata` would leak a recovered
  prototype into its callers' decompiles.
* `QueryCommands.decompile` gives the decompiler and its gate permit back once the result is decoded and
  before the C text is printed (D9). The reply is unchanged.
