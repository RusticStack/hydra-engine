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

- The file holds the bytes `Memory.getBytes` returns: initialized, unmapped blocks of byte-addressable spaces, with
  adjacent blocks of one space merged (as `Memory.getBytes` reads across them).
- A request is served from the file only when the **whole** range lies in one region. Partial ranges (where the
  callback returns the read part plus zeros), uninitialized or mapped blocks, word-addressed spaces and register
  addresses all go to the callback, unchanged.
- The file is written for one modification number and checked again after writing; a program that changed while it
  was written gets no snapshot. Each decompile compares the modification number and moves to a new file when it
  changed, so the process never reads bytes older than the program.
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
- Snapshot files live in `java.io.tmpdir/hydra-decompiler-snapshots`; a JVM that is killed leaves them behind
  (`deleteOnExit` covers normal exits). A daemon should clean the folder at start.
- With frequent edits the file is rewritten per modification number; for the daemon this wants an incremental
  generation (byte-change events) before the flag can default on.
