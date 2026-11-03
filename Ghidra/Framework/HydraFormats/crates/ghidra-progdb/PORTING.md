# ghidra-progdb porting notes

Source: `ghidra.program.database.ProgramDB` (open, version policy, metadata map via
`DBStringMapAdapter`), `map.AddressMapDB` + `AddressMapDBAdapterV1`, `mem.MemoryMapDBAdapterV3`,
`MemoryBlockDB`, `SubMemoryBlock`, `symbol.SymbolDatabaseAdapter` (V4/V5 record layout).
Read-only. Upgrades stay in Java.

## Status

| Java | Rust | State |
| --- | --- | --- |
| `ProgramDB` open: stored version check (`DB_VERSION` 33, `UPGRADE_REQUIRED_BEFORE_VERSION` 19) | `ProgramDb::open`, `ProgError::{NewerVersion, UpgradeRequired, UnsupportedTableVersion}` | done; 19..=33 opens (Java opens 19..32 read-only through old adapters), anything else is refused |
| "Program" string map (`Language ID`, `Compiler Spec ID`, `Image Offset`, `DB Version`, ...) | `ProgramDb::metadata`, `language_id`, `compiler_spec_id`, `image_base_offset` | done |
| `AddressMapDBAdapterV1` + `AddressMapDB.decodeAddress` | `AddressMap::decode` | done for absolute, relocatable (image base, wrap), register, stack, external, variable, hash, `NO_ADDRESS`, `EXT_FROM`. NOT ported: old key type 0, namespace-qualified register/stack/external keys (`OldGenericNamespaceAddress`), segmented spaces, overlay spaces |
| `AddressMapDB.getKey` / encode | none | NOT ported (read-only) |
| `MemoryMapDBAdapterV3`, `MemoryBlockDB.refresh` | `ProgramDb::memory_blocks`, `MemoryBlock`, `SubBlock` | done (sorted by start address). Overlay detection, mapped-block targets and `isInitialized` of mapped blocks (Java asks the source) are NOT ported |
| `FileBytes` table | none | NOT ported (blocks reference it by id only) |
| `SymbolDatabaseAdapterV4/V5` record layout, `SourceType` flag decoding | `ProgramDb::symbols`, `Symbol` | done; `is_primary`/`is_pinned` follow the Java symbol classes. Names of default-named symbols are stored empty (Java computes `FUN_`/`LAB_` names; not ported) |
| `SymbolManager` queries (by name, namespace paths, references) | none | NOT ported |
| listing: Instructions, Data, Comments, Functions, references, equates, data types | none | NOT ported (tables exist in the fixtures but are only visible through `database()`) |
| older table versions (symbol V0..V3, memory V0..V2, address map V0) | `UnsupportedTableVersion` | refused on purpose: Java upgrades these |

## Address spaces

The database stores space names only. The caller passes `AddressSpaces` (name, id, bits, default
space) taken from the language; the differential test reads them from the oracle output. The
static `EXTERNAL`, `VARIABLE` and `HASH` spaces are added when missing.

## Tests

* `tests/oracle_diff.rs`: for both checked-in v32 fixtures (`legacy-12.1.4`,
  `legacy-12.1.4-analysed`) compares stored version, language, compiler, image base, every memory
  block with its sub blocks (name, start, end, size, flags, comment, source, parts) and every row
  of the symbol table (385 and 2912 rows: id, name, decoded address, parent, type, source,
  primary, pinned) with `testdata/oracleprog-*.txt`. Those files come from
  `oracle/OracleProgram.java`, which opens the same files through the stock Ghidra 12.2
  `ProgramDB` (`OpenMode.IMMUTABLE`). See `oracle/README.md` for the command line.
* `tests/versions.rs`: a copy of the fixture with the stored version patched to 33, 19, 34, 18
  and 10 opens or is refused with the expected error.
* There is no v33 fixture in the repository; v33 is covered only by the patched-version test (the
  table layouts of 32 and 33 are the same in the files we have).
* Not covered: refusal of old table versions (no fixture has one), overlay and mapped blocks,
  segmented spaces.
