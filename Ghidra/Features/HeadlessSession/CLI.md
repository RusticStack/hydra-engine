<!--
# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
-->

# `hydra`: the Hydra Engine as a command line for coding agents

`hydra` is one binary (crate `rust/crates/hydra-client`, `src/bin/hydra/`) that opens, imports,
analyses and queries programs through the headless daemon. It is a client of the session protocol
(README.md "Protocol", PROTOCOL-3.md) built on the same `hydra_client` library as `hydra-agent`;
it adds no server and no second protocol stack. It never starts a GUI, never prompts, and prints
one JSON object per command on stdout.

Windows x64 only (the daemon launcher it uses is the install's `ghidra_session.py`, so Python 3
must be on `PATH`, or named with `--python`).

## Contents

1. [Quick start](#quick-start)
2. [Output and exit codes](#output-and-exit-codes)
3. [Commands](#commands)
4. [Selecting a project and program](#selecting-a-project-and-program)
5. [Daemons and backends](#daemons-and-backends)
6. [Several agents at once](#several-agents-at-once)
7. [GUI coupling](#gui-coupling)
8. [Tests](#tests)
9. [Limits and what is not done](#limits-and-what-is-not-done)

## Quick start

```
set HYDRA_GHIDRA=C:\ghidra_12.3_DEV            (or run hydra.exe from <install>\Ghidra\Features\HeadlessSession\support)
hydra import C:\Windows\System32\choice.exe --project D:\re\choice.gpr --analyze
hydra functions --contains entry
hydra decompile entry
hydra disasm entry --text
hydra xrefs 0x140001300 --direction both
hydra shutdown
```

`import` creates the project when it does not exist, starts the daemon when none runs, imports,
analyses (`--analyze`) and remembers project and program for the commands that follow. Real output
from the lane's run (`D:\Projects\Hydra\_data\cli-lane`, `choice.exe` from System32, abridged):

```
$ hydra decompile entry
{"backend":"full","command":"decompile","ms":16,"ok":true,"result":{"c":"\r\nvoid entry(void)\r\n\r\n{\r\n  FUN_140001734();\r\n  FUN_140001140();\r\n  return;\r\n}\r\n\r\n","completed":true,"entry":"0x140001300","name":"entry","signature":"void entry(void);","truncated":false}}

$ hydra disasm entry --text
0x140001300  4883ec28             SUB RSP,0x28
0x140001304  e82b040000           CALL 0x140001734
0x140001309  4883c428             ADD RSP,0x28
0x14000130d  e92efeffff           JMP 0x140001140

$ hydra function nope ; echo %ERRORLEVEL%
{"command":"function","error":{"code":"not_found","details":{},"message":"no function named nope"},"exit":3,"ok":false}
3
```

## Output and exit codes

Every command prints exactly one JSON object on stdout and nothing on stderr (`--json`, the
default). `--text` prints a plain rendering of the result to stdout (the C text for `decompile`,
one instruction per line for `disasm`, a hex dump for `bytes`, ...) and failures to stderr.

Success:

```json
{"ok": true, "command": "functions", "backend": "full", "ms": 21, "result": { ... }}
```

`backend` is `full`, `lite`, or `none` (commands that need no daemon). `ms` is the command's
wall time inside the process, not counting process start.

Failure:

```json
{"ok": false, "command": "info", "exit": 7,
 "error": {"code": "no_context", "message": "no project selected", "details": {}, "hint": "..."}}
```

`error.code` is the engine's own code when the engine sent one (`not_found`, `busy`, `read_only`,
...), or one of `usage`, `no_context`, `no_daemon`, `no_install`, `no_launcher`, `no_python`,
`launch_failed`, `launch_timeout`, `script_unavailable`, `output_truncated`, `use_full_daemon`.
`details` is the engine's `error.details`; `hint` says what to do about it when there is something.

| Exit | Meaning | Engine / client codes |
|---|---|---|
| 0 | success | |
| 1 | the engine failed the request | `failed` and any code not listed below |
| 2 | wrong command line | `usage`, `bad_request`, `unknown_command` |
| 3 | not found: function, address, program, project | `not_found` |
| 4 | no daemon: cannot find, start or reach one; install or launcher unusable | `no_daemon`, `no_install`, `no_launcher`, `no_python`, `launch_failed`, `launch_timeout`, `script_unavailable`, `io`, `closed`, `unauthorized` |
| 5 | busy, timed out or cancelled | `busy`, `cancelled`, `deadline_exceeded` |
| 6 | the daemon speaks a protocol this client does not | `incompatible` |
| 7 | no project or program selected | `no_context`, `no_project`, `no_program` |
| 8 | the engine refused | `read_only`, `not_owner`, `conflict`, `unsaved_changes` |
| 9 | the command needs the full daemon but `--backend lite` was given | `use_full_daemon` |

The numbers are a contract: new conditions get new numbers, existing ones are never renumbered.
`hydra status` and `hydra shutdown` exit 0 when nothing is running.

## Commands

Global options go anywhere on the line. `<addr|name>` is an address (`0x140001000`, `va:0x...`,
`rva:0x1000`, `space:offset`) or a function name; a token spelled like an address is an address.

| Command | Does | Needs |
|---|---|---|
| `open <project.gpr> [--program NAME] [--create]` | selects a project (and program) and remembers it; `--create` makes an empty project when missing | |
| `import <file> [--analyze] [--folder F] [--name N] [--language L] [--compiler C] [--duplicate] [--timeout S]` | imports into the selected project (created when missing) and remembers the program; `--analyze` runs auto-analysis; a file the project already holds answers `imported:false` unless `--duplicate` | project |
| `analyze [--timeout S]` | auto-analyses the selected program and saves | project, program |
| `status` | the daemons that run (full, lite), their endpoint and, for the full one, the engine's `status`; starts nothing | |
| `start` | starts the daemon (`--backend lite` starts `hydra-lite`) | |
| `shutdown [--force]` | stops the full and the lite daemon; `--force` even while other clients are connected | |
| `info` | language, compiler, image base, hashes, function count, analysed | project, program |
| `list [--folder F] [--limit N] [--offset N]` | the project's folders and programs | project |
| `functions [--contains S] [--limit N] [--offset N]` | functions by name filter, address order | project, program |
| `function <addr\|name>` | signature, bounds, size, calling convention, parameters, stack frame, caller/callee/reference counts | project, program |
| `decompile <addr\|name> [--timeout S] [--max-chars N]` | C text (`result.c`) | project, program |
| `disasm <addr\|name> [--count N]` | a whole function when given a name, else `--count` (default 64) instructions from an address; data and undefined bytes are listed as such | project, program |
| `xrefs <addr\|name> [--direction to\|from\|both] [--limit N]` | references to (default), from, or both, with the containing function | project, program |
| `callers <addr\|name> [--limit N]` | flow references to the function's entry, with the calling function | project, program |
| `callees <addr\|name>` | functions the function calls | project, program |
| `strings [--min N] [--contains S] [--limit N] [--offset N]` | defined string data | project, program |
| `imports [--contains S] [--library L] [--limit N] [--offset N]` | external locations, with the IAT slots that reference them | project, program |
| `bytes <addr\|name> [--len N]` | up to 65536 bytes as hex and ASCII | project, program |
| `search --hex 'AA BB ?? CC' \| --text S [--wide] \| --name S [--limit N]` | byte pattern (`??` wildcard), text (UTF-8, or UTF-16LE with `--wide`), or function name substring | project, program |
| `version`, `help` | | |

List-type results carry `truncated` (and `total` or `count`); raise `--limit` or page with
`--offset`. A result too large for the script output cap (16,000,000 characters) is refused as
`output_truncated`, never cut.

### Examples

```
hydra open D:\re\choice.gpr --program choice.exe        # select; later commands need no flags
hydra callers FUN_140001140 --text                      # 0x14000130d -> 0x140001140  UNCONDITIONAL_CALL  entry
hydra callees entry
hydra strings --contains PARSER --limit 5
hydra imports --library KERNEL32.DLL --contains Create
hydra bytes 0x140001300 --len 16 --text                 # 0x140001300  48 83 ec 28 e8 2b 04 00 ...
hydra search --hex "4d 5a ??" --limit 3                 # matches carry block and containing function
hydra --project D:\re\a.gpr --program /a.exe decompile main     # explicit, no remembered state
hydra analyze --timeout 1800
```

Queries the protocol has no command for (`function`, `disasm`, `xrefs`, `callers`, `callees`,
`strings`, `imports`, `bytes`, `search`) run `HydraCli.java`, a read-only GhidraScript embedded in
the binary (`src/bin/hydra/HydraCli.java`). The command publishes it to `<state>\hydra-cli\` and adds
that folder to `scriptPath` in `<state>\config.json` (other keys are kept; an unreadable
`config.json` is never overwritten) before it starts a daemon. A daemon that was already running
without that path answers `script_unavailable` (exit 4); run `hydra shutdown` and retry.

## Selecting a project and program

A command acts on one project and one program. They come from, in order: `--project` / `--program`,
`HYDRA_PROJECT` / `HYDRA_PROGRAM`, then the context file written by `open` and `import`
(`<state>\hydra-cli-context.json`, or the file named by `HYDRA_CONTEXT`). Nothing selected is
exit 7 with a hint, and the daemon is not contacted. Each invocation opens the project read-only
and the program on its own connection (selections do not outlive a connection); the daemon keeps
them warm (`keepWarm`, 600 s in the lane), so this costs milliseconds.

Several agents sharing one state directory should not share the context file: give each its own
(`HYDRA_CONTEXT=C:\agents\a1\ctx.json`) or pass `--project` / `--program` on every call.

## Daemons and backends

| Option / variable | Meaning |
|---|---|
| `--state DIR`, `HYDRA_STATE`, `GHIDRA_SESSION_HOME` | state directory (endpoint files, logs, `config.json`); default `%LOCALAPPDATA%\GhidraSession` |
| `--ghidra DIR`, `HYDRA_GHIDRA`, `GHIDRA_INSTALL_DIR` | install; default: the install around `hydra.exe` if it sits in `support\` |
| `--instance NAME`, `HYDRA_INSTANCE` | daemon instance, default `hydra` (full) and `hydra-lite` |
| `--backend auto\|full\|lite` | see below |
| `--no-start` | never start a daemon: exit 4 `no_daemon` |
| `--deadline S`, `HYDRA_DEADLINE` | client-side deadline of each request, default 600 |
| `--python EXE`, `HYDRA_PYTHON` | interpreter for the launcher (default `python`, `python3`, `py`) |
| `--lite-bin`, `HYDRA_LITE`; `--front-bin`, `HYDRA_FRONT` | `hydra-lite.exe` / `hydra-front.exe`; default: beside `hydra.exe` |

Starting is attach-first: if `<state>\<instance>.json` names a daemon that answers `hello`, it is
used; otherwise the install's launcher is run (`ghidra_session.py --instance NAME ensure`), which
owns the JDK choice, the class cache and the process hand-off, and the command waits for it (up to
240 s). Nothing is started by `status`, `shutdown`, `help`, `version` or `--no-start`.

Backends (README "hydra-lite", HYDRA-LITE.md):

* `auto` (default). Read-only commands that `hydra-lite` can serve (`open`, `list`, `info`,
  `functions`) go to the lite daemon **when it is running**; if it answers `use_full_daemon` for
  anything in the sequence (`open_program` of a program it cannot present exactly, for example)
  the whole sequence is repeated on the full daemon and the result says `"backend":"full"`.
  Everything else (`decompile`, the script-backed queries, `import`, `analyze`) uses the full daemon,
  starting it when needed. Auto never starts `hydra-lite` itself.
* `full`: the full daemon only.
* `lite`: `hydra-lite` only, started if needed; a command it cannot serve is exit 9, a refusal
  by the lite daemon is exit 9 with the engine's `details.reason`.

`hydra start --backend lite` starts `hydra-lite`. It reads the engine identity from a cache that a
real daemon of the same command line writes; when the cache is missing it runs `hydra-front` once
for the same instance (which starts the JVM, learns the identity and is then stopped) and starts
`hydra-lite` again. That is a one-time cost of one JVM start per install and state directory.

## Several agents at once

Each invocation is its own client connection; the daemon's own rules apply (README "Several
clients"): reads run in parallel, a writable project (`import`, `analyze`) is owned by one client
while it writes and read-only joins keep working. Two agents importing into the same project at
the same time are serialised by the engine. The CLI keeps no lock of its own. `busy` is exit 5 and
safe to retry.

## GUI coupling

Question: what GUI code (Docking, Gui, Swing/AWT, Help, front-end Tool/PluginTool modules) does
the headless daemon load, at start and per request, and what does that cost?

### Method (all numbers measured unless marked)

Install `E:\Projects\Hydra\wt\h7-int\build\dist\ghidra_12.3_DEV` (12.3-hydra.7-gate, read-only), own
state directory `D:\Projects\Hydra\_data\cli-lane\audit-state`, the launcher's exact JVM command
line (`ghidra_session.py command`: JDK 25.0.4, `-Djava.awt.headless=true`, class cache hit, fast
mode) with `-Xlog:class+load` added and the launcher's `-Xlog:disable` removed. Workload on one
connection: `hello`, `open_project`, `open_program`, `functions`, `decompile`, five more decompiles,
two `script` calls. `choice.exe`, analysed, 174 functions. Memory is the process working set and
private bytes from `Get-Process` after each step. Tools: `audit.py`, `an.py`, `Probe.java` and the
raw logs are in `E:\Projects\Hydra\_logs\h7\cli\audit\`. One machine, shared with other lanes, so
single timings are noisy; the timing figures below are from 3 to 5 runs.

### What is loaded

The JVM loads 8,274 classes by the end of the workload. **192 of them (2.3 %) are GUI-package
classes**: `java.awt`, `javax.swing`, `javax.accessibility`, `sun.awt`, `docking`, `generic.theme`,
`help`, `ghidra.framework.main`, `ghidra.framework.plugintool`, `ghidra.app.plugin.core` (without
`osgi`, which the script compiler needs), `java.beans`. By step:

| Step | New classes | GUI classes |
|---|---|---|
| start to ready (1.3 s) | 4,992 | 108 |
| `hello` | 79 | 0 |
| `open_project` | 1,337 | 77 |
| `open_program` | 1,456 | 6 |
| `functions` | 77 | 0 |
| first `decompile` | 225 | 0 |
| five more `decompile` | 37 | 0 |
| `script` (disasm, strings) | 58 | 1 |

So the GUI cost is paid once, at start and at the first project open; **steady-state requests load
no GUI classes**.

Where they come from (class names from the load log, source from the code):

* Start-up, 108 classes: the stock `HeadlessGhidraApplicationConfiguration.performModuleInitialization`
  instantiates every `ModuleInitializer` on the class path. Two are GUI-only:
  `docking.options.editor.EditorInitializer` (registers AWT property editors: `ColorEditor`,
  `FontEditor`, `FileChooserEditor`, ... which pull in `java.awt.Color`/`Font`/`Component`/`Container`,
  `javax.swing.JComponent`/`JPanel`, `docking.widgets.tree.GTree`, `ghidra.framework.main.datatree.*`)
  and `decompiler.DecompilerInitializer` (registers `DecompilerCommentsActionFactory`, a Docking
  action factory; loads `docking.action.DockingAction`, `help.HelpDescriptor`,
  `CommentsActionFactory`). Loading `java.awt.Color` loads `awt.dll` (and with it `user32`,
  `gdi32` and `comctl32` are among the process's libraries; which of them `awt.dll` pulled in was not
determined).
* `open_project`, 77 classes: `generic.theme.*` (`ThemeManager`, `StubThemeManager`, `GTheme`,
  built-in Mac/Windows/FlatLight themes), `ghidra.framework.main.AppInfo`,
  `javax.swing.filechooser.*`, from the project manager.
* The other `ModuleInitializer`s in the tree (`Generic`, `DefaultSSLContext`, `DB`, `FileSystem`,
  `Project` (registers the `ghidra` URL handler), `SoftwareModeling`, `BSim`, `Foundation`) have no
  GUI class in their `run()` as read from source; `Project` and `Generic` were read, the rest only
  by name.

What does **not** happen: `awt.dll` is the only AWT native library loaded (`VM.dynlibs`: no
`fontmanager`, `freetype`, `lcms`, `javajpeg`, `splashscreen`); no AWT event-dispatch thread
exists (`Thread.print` shows only `GhidraSwinglessTimer`); no window, tool, or `PluginTool` is created;
`flatlaf`, `javahelp`, `timingframework` jars are on the class path but no class from them is
loaded; the Debugger, FunctionGraph, DataGraph and CodeCompare jars are on the class path (139 jars
in all) and the only classes loaded from them are two ISF data-type classes of `Debugger-isf.jar`
(`IsfObject`, `AbstractIsfObject`, loaded at `open_program`), which are not GUI.

### What it costs

* Whole daemon, plain run without class logging (4 runs): ready after **1.2 to 1.4 s**
  (launcher-reported `readyMs` 0.7 to 0.8 s), **142 to 145 MB working set, 165 to 167 MB private,
  38 to 39 threads**; after the workload 250 to 260 MB working set, 270 to 278 MB private, 74
  threads. These include everything, not only the GUI classes.
* The GUI classes alone (`Probe.java`, fresh JVM, same class path, the 206 GUI-package class names
  loaded by name, 5 runs each): **46 to 66 ms and 1.8 MB of metaspace to load, 78 to 84 ms and
  3.8 MB to load and initialise** (one cold first run took 1.1 s, awt.dll from disk). The probe
  includes the superclasses it pulls in, so it is an upper bound of what removing the GUI classes
  would save: **at most about 4 to 6 % of the 1.3 s start-up and 1 to 2 % of the private memory**.
  There is no way to separate the share inside the running daemon more precisely than this.
* Per request: zero GUI classes (table above).

### What can be removed, and what is proven

* **`Docking.jar` cannot be dropped from the class path.** Measured: starting the daemon without
  `Docking.jar`, `Gui.jar`, `Help.jar`, `javahelp`, `flatlaf`, `timingframework` fails during
  application initialisation with `NoClassDefFoundError: docking/action/DockingAction` at
  `decompiler.DecompilerInitializer.run` (`HeadlessGhidraApplicationConfiguration.performModuleInitialization`).
  That is a real dependency of the headless start-up path.
* **Dropping the GUI feature jars gains nothing.** Measured: removing `FunctionGraph`, `DataGraph`,
  `CodeCompare`, `GraphServices`, `Debugger`, `Debugger-api`, `Debugger-importers`, `Debugger-isf`,
  `Debugger-rmi-trace`, `TaintAnalysis`, `VersionTrackingBSim` from the class path, the same workload
  ran without errors (including the two `Debugger-isf` classes, which the workload did not need),
loaded 8,271 instead of 8,274 classes and was not faster (ready 1.68 s versus
  1.33 s with the full class path in the same logging mode, private memory 163 to 166 MB versus
  166 MB). They are only scanned, not loaded, and the scan is skipped by the class cache. This proves
  only that this workload does not touch them; it does not prove the rest of the contract tests do
  (VersionTracking, for one, is used by scripts and is left alone). **Not proposed.**
* **Proposal, not applied and not proven: skip the two GUI `ModuleInitializer`s** (`EditorInitializer`,
  `DecompilerInitializer`) in `SessionApplicationConfiguration`, by running the initialisers whose
  class is not in a GUI package. That would remove most of the 108 start-up GUI classes and `awt.dll`.
  What is missing for a proof: a rebuilt `HeadlessSession.jar` and a run of `contract_tests.py`,
  `client_compat_tests.py`, `session_smoke.py` and the golden 9.1 comparison against it. This lane
  was forbidden to run Gradle, so the change was not made. The expected gain is bounded by the probe
  above (tens of milliseconds, a few MB), so it is a tidy-up, not a performance fix. Nothing in the
  tree was changed for this audit.

The class-loading cost of the GUI is therefore small and one-time; the daemon's start-up and memory
are dominated by the JVM, the class path scan, Sleigh and the decompiler host.

## Tests

`cargo test` in `rust/`:

* `src/bin/hydra/*.rs` unit tests (31): argument parsing and every usage error, the exit-code table,
  environment and context resolution, script publication and `config.json` merging (including the
  refusal to clobber an unreadable one), script answer parsing, `--text` rendering, launcher
  helpers.
* `tests/hydra_cli.rs` (18): the binary against fake daemons: request sequences, read-only opens,
  address versus name for `decompile`, script argument passing and error mapping, every engine code to
  its exit, no contact without a selection, `--no-start`, `help`/`version`, `open` remembering the
  selection, lite-first routing, the `use_full_daemon` fall-back (both daemons see the full sequence),
  `--backend full` and `--backend lite` rules, `shutdown --force`, `status`.

The real daemon run described above (import, analyse, every command, lite and full, cold start)
was done by hand with the built install; it is not an automated test, because it needs the install.

## Limits and what is not done

* `hydra.exe` is not yet installed by `build-install.py` (it builds and installs `hydra-agent` and
  `hydra-etw`); build it with `cargo build --release -p hydra-client --bin hydra`.
* The launcher is Python. A Rust launcher (JDK discovery, class cache, hand-off) would remove that
  dependency; it would duplicate `ghidra_session.py` and was not attempted.
* The script-backed queries need the daemon to have been started with the script folder; a daemon
  started by another tool needs one `hydra shutdown`.
* `hydra-lite` refuses what it cannot present exactly: the lane's analysed `choice.exe` (functions in
  a namespace) falls back to the full daemon; un-analysed `hostname.exe` and `whoami.exe` are served by
  the lite daemon (engine time 16 to 19 ms for `info`).
* Writes beyond `import` and `analyze` (rename, comment, signature, edits, forks, overlays) are not in
  the command line; they are protocol commands the shipped clients already have.
* No streaming: a result is one JSON object.
* Measurements on this page are one machine, shared with other lanes.
