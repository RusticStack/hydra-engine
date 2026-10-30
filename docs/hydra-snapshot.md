# Decompiler snapshots (sealed-generation program files)

Status: **prototype, off by default** (`-Dhydra.decompiler.snapshot=true` turns it on). Plan ranks 7 and 12
(`hydra-rust-plan.md`, `_logs/rust-phase0/phase0-reading-report.md`: D3, D10, E11-E13).

## Why

Every `decompile.exe` process asks Java for the program's bytes, symbols, types and p-code one callback at a time
(`DecompileProcess` callback loop, D3). Each answer is a pipe round trip plus a database read that takes the
program's locks, so N decompiler processes take turns in Java. A **sealed generation** of the program (its state at
one modification number) never changes, so it can be written once to a file and read by every process and thread at
the same time with no lock and no round trip.

## What exists now (step 1: bytes)

| piece | file | role |
|---|---|---|
| writer | `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/ProgramSnapshotFile.java` | writes the file for the program's current modification number; one shared file per program and generation, leased by every `DecompInterface` that uses it, deleted when the last lease is released |
| wiring | `DecompInterface.syncSnapshot` | before each `decompileAt`: lease the current generation's file (rewritten when the modification number changed) and send `setSnapshot <path>`; with the flag off, or while a `DecompileDebug` dump is recording, the process is told to drop it |
| C++ reader | `cpp/loadimage_ghidra.cc` `SnapshotImage`, `LoadImageGhidra::loadFill` | maps the file read-only; `loadFill` serves a request from the map when one region holds the whole range, otherwise it calls back to Java exactly as before |
| command | `cpp/ghidra_process.cc` `SetSnapshot` (`setSnapshot`) | installs or drops the snapshot of a registered program; answers `t`/`f`; a file it cannot map leaves the process on callbacks |
| Rust reader | `Ghidra/Framework/HydraNative/crates/hydra-snapshot` (memmap2) | the same format for Rust components; `Snapshot` is `Send + Sync`; C ABI `hysnap_open/close/generation/space_index/read/read_bulk` for FFM and C |
| A/B tool | `Ghidra/Features/Decompiler/ghidra_scripts/SnapshotABScript.java` | decompiles every function with the flag off and on in alternating passes, compares the C text, counts `getBytes` callbacks (`DecompileProcess.getBytesCallbackCount`) and times each pass |

### Why the output cannot change

- The file holds the bytes `Memory.getBytes` returns: initialized, unmapped blocks of byte-addressable loaded memory
  spaces (not OTHER sections such as `.comment` or `.debug_*`), with adjacent blocks of one space merged (as
  `Memory.getBytes` reads across them; `MemoryMapDB.getBytes` reads each block through `MemoryBlock.getBytes`, which is
  what the writer uses). Only `ProgramDB` programs get a snapshot; other `Program` views stay on callbacks.
- A request is served from the file only when the **whole** range lies in one region. Partial ranges (where the
  callback returns the read part plus zeros), uninitialized or mapped blocks, word-addressed spaces and register
  addresses all go to the callback, unchanged.
- The file is written for one modification number and checked again after writing; a program that changed while it
  was written gets no snapshot. Each decompile compares the modification number and moves to a new file when it
  changed. This is best-effort under concurrent edits: the modification number is bumped after a change is written
  and is read without the program lock, so a decompile that races with a byte edit can see the bytes from before or
  after it, as the callback path can. Without concurrent edits the bytes are those of the current program.
- The file is written outside the per-program lock: while one thread writes a generation, other interfaces of the
  same program use callbacks for that decompile instead of waiting.
- A process that rejects a file (`f`) is not sent it again; a decompiler without the `setSnapshot` command (an
  older `decompile.exe`) stays on callbacks for the life of that process.
- `DecompileDebug` dumps need every byte request; while one records, the snapshot is dropped.

### File format (version 1, little-endian)

```
 0  magic "HYSNAP01"      8  u32 version = 1     12  u32 space count
16  u32 region count     20  u32 reserved = 0   24  u64 generation (program modification number)
32  region table: per region  u32 space index, u32 reserved, u64 offset, u64 length, u64 data offset
    space table: per space    u32 byte length, UTF-8 space name (Ghidra AddressSpace name = C++ AddrSpace name)
    data, 8-byte aligned start: the bytes of each region at its data offset
```

Regions are sorted by (space index, offset) and never overlap; readers reject anything else, a bad version, or a
table or region that runs past the end of the file.

### Measured (2026-10-30, quick A/B on a loaded machine, not a profile)

`SnapshotABScript` (fixed golden options, one sequential `DecompInterface`, passes off/on/off/on in one JVM) on
copies of the gate-1 fixture projects and the first 400 non-thunk functions of KotOR (`swkotor.exe`):

| program | functions | C output on vs off | getBytes callbacks per pass off -> on | wall ms per pass (off, on, off, on) |
|---|---|---|---|---|
| x64 diff1 | 487 | identical | 994 -> 1 | 9971, 6286, 5886, 7478 |
| x64 diff2 | 487 | identical | 994 -> 1 | 7389, 6129, 6621, 7016 |
| x64 flow | 387 | identical | 916 -> 1 | 4614, 3784, 3662, 3612 |
| x64 vcall | 401 | identical | 914 -> 1 | 4721, 3569, 3517, 3479 |
| x86 diff1 | 575 | identical | 507 -> 0 | 8366, 7335, 6047, 5866 |
| x86 diff2 | 575 | identical | 507 -> 0 | 8655, 6735, 6425, 5645 |
| x86 flow | 465 | identical | 456 -> 0 | 4482, 3524, 3415, 3618 |
| x86 vcall | 481 | identical | 452 -> 0 | 4770, 3692, 7582, 5551 |
| KotOR (400) | 400 | identical | 628 -> 0 | 6820, 5662, 5415, 6479 |

Every byte callback but one per x64 program (a range the snapshot does not hold whole) is gone. Wall time does not
move beyond the noise of a busy machine: byte queries are a small share of the callbacks (p-code dominates), so the
gain this step unlocks comes with the p-code section below. The engine-written files validate with the Rust reader
(`HYSNAP_SAMPLE=<file> cargo test --test snapshot engine_written`).

## Snapshot reads in the engine JVM (`hydra.memory.snapshotReads`, default off)

Plan goals 1 and 3 (immutable shared data, no JVM heap for hot data). With
`-Dhydra.memory.snapshotReads=true`, every program `HeadlessSession` opens **read-only** (also from the upgrade cache,
and the read-only reopen after a writer leaves) serves its byte reads from the same snapshot file instead of the
database buffers:

| piece | file | role |
|---|---|---|
| hook | `SoftwareModeling/.../mem/MemoryReadSnapshot.java`, `MemoryMapDB.setReadSnapshot`, `MemoryBlockDB.getBytes(long..)` / `getByte(long)` | the block read paths ask the installed snapshot first; it answers only a range it holds whole, otherwise the database is read as before. Every `Memory.getBytes/getByte/getShort/getInt/getLong`, `MemoryBlock.getBytes/getByte` and `MemBuffer` read goes through these two methods, including FileBytes-backed blocks (original and modified file bytes) |
| guard | `MemoryMapDB.activeReadSnapshot` | used only while `program.getModificationNumber()` equals the snapshot's generation. Dropped (and unmapped) **before** the database changes: in `checkMemoryWrite` before bytes are written, at the start of every block create/move/split/join/convert/remove, and in `ProgramDB.beforeUndoRedo` (called by the transaction manager before `dbh.undo()/redo()`); also on bytes/block events and reloads. After the drop no read starts on the mapping; a read already in progress returns the bytes from before that change. A snapshot left behind by a non-memory change (generation older than the program) is dropped and its file released on the next read |
| reader | `Decompiler/.../MappedProgramSnapshot.java` | leases the generation's file from `ProgramSnapshotFile` (the same shared file the decompiler processes map), maps it once with `FileChannel.map(READ_ONLY, .., Arena.ofShared())`, parses and validates the v1 tables, copies with `MemorySegment.copy`. Reads hold a reference; the arena is closed only after the snapshot is detached and the last read ends, then the lease is released (so Windows can delete the file) |
| wiring | `HeadlessSession ProgramCommands.openReadOnly` / `releaseProgramObject` | attach after every read-only open, close with the program object |

Proof: `MappedProgramSnapshotTest` (test.slow) and `SnapshotReadsABScript` (exhaustive compare of every byte of every
block through `Memory.getBytes`, `MemoryBlock.getBytes` and `getByte`, plus cross-block reads, database vs mapping,
then 8 concurrent readers off/on/off/on with the same seeded reads, whose checksums must match). Results are in the
p6-offheap-mem report (`_logs/rust-integration/offheap-mem.md`).

Not covered: direct `FileBytes.getOriginalByte(s)/getModifiedByte(s)` calls that bypass memory blocks (exporters) still
read the database; writable and shared programs never get a snapshot.

## Extending to a callback-free decompiler (rank 12)

The order follows the expected callback volume per decompiled function (D3: one p-code query per instruction, one
byte query per load image fill; symbols and data types per referenced object; comments, string data, tracked
registers, cpool and inject payloads are rarer). The Phase 0 P4 callback counts confirm or reorder it.

1. **Sections, not new files.** Version 2 adds a section directory after the header (`u32 kind, u64 offset, u64 size`)
   so one file per generation carries every table; v1 readers stay valid for bytes because the region table keeps its
   place. Each section is a sorted, fixed-width index plus a blob heap (strings, packed encodings), so every lookup is
   a binary search over mapped memory, with no parsing and no allocation.
2. **P-code** (`getPcodePacked`, one callback per instruction, the largest share). Export the *packed* p-code the Java
   side already produces (`DecompileCallback.getPcodePacked`, including `InstructionPcodeOverride`, flow overrides and
   the `undefinedBody` cases) per instruction address for every function body and every address the analysis
   reached, keyed by address, value = the exact packed bytes the callback would send. `GhidraTranslate::oneInstruction`
   looks the address up first and falls back to the callback for anything missing (code reached only by the
   decompiler's own flow). Do **not** run C++ Sleigh on the snapshot instead: its answers can differ from the
   database's (overrides, context), the high-risk path in the Phase 0 report.
3. **Symbols and scopes** (`getMappedSymbolsXML`, `getNamespacePath`, `getExternalRef`, `getCodeLabel`,
   `isNameUsed`): export per function the encoded answers the callbacks give for its entry, its body addresses and the
   globals it references, keyed by (query, address). `ScopeGhidra` consults the section before the callback. The
   answers depend on decompiler options (name transformer) and are written for the options in force; a different
   option set uses a different file.
4. **Data types** (`getDataType`, `getComments`, `getStringData`, `getTrackedRegisters`): the same pattern, keyed by
   type id / address. Types are global, so they are written once per generation, not per function.
5. **What stays a callback:** inject payloads (`getPcodeInject` with run-time context), constant-pool queries
   (`getCPoolRef`, Java/Dalvik only) and anything a section does not hold. A process with every section in use makes
   no callback for ordinary x86/x64 code, so the Java side no longer serialises N processes.
6. **Host.** With all inputs in the file, `decompile.exe` no longer needs the Java process during a decompile. A Rust
   host (rank 12 XL) can then run one C++ `Architecture` per worker thread (one Sleigh per thread, sleigh.hh:168-172;
   `countbase` and the global `archlist`/`commandmap` stay per process or become thread-local, D10) over the same
   mapping, and the Rust reader in `Ghidra/Framework/HydraNative/crates/hydra-snapshot` serves the Java side and analysers through FFM.

Every step keeps the fallback: a section that is missing, older than the program, or does not hold the key sends the
query to Java, so a partial snapshot is always correct and only fewer callbacks are saved.

### Proof required for each step

- The A/B tool (or the golden 9.1 diff) gives identical C output with the flag on and off on the fixture set and KotOR.
- The callback count for the moved query type drops to the fallback cases only.
- A DecompileDebug replay (`decompile_dbg`) of the same functions with the file mapped gives the same output.

## Open items

- The C++ reader is a small in-tree copy of the format (no Rust in `decompile.exe` yet); once the Rust workspace from
  `rust/p1-native-core` is in the build, the C++ side can link the `hydra-snapshot` C ABI instead, or keep the copy and
  test both against the same files (`HYSNAP_SAMPLE=<file> cargo test` validates an engine-written file).
- Snapshot files live in `java.io.tmpdir/hydra-decompiler-snapshots`. A shutdown hook deletes every file this JVM
  still holds, including those leased by a `DecompInterface` that was never disposed; a JVM that is killed leaves
  them behind. A daemon should clean the folder at start (not done here: other JVMs share the folder).
- The generation is the program modification number, which every change bumps (symbols, comments, types too), so
  during auto-analysis the file is rewritten for almost every decompile. Not for use during auto-analysis: before the
  flag can default on, the generation must follow memory changes only (block and byte change events) and be written
  incrementally.
- Conformance: the Java writer (`ProgramSnapshotFileTest`) and the Rust reader (`golden_v1_conformance`) are tested
  against the same 128-byte vector; the C++ reader is covered only by the decompile test with the flag on.
