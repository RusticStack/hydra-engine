# ghidra-fmt-db porting notes

Source: `db.DBHandle` (open path), `MasterTable`, `TableRecord`, `Table` (read side), `IndexTable`,
`FieldIndexTable`.

## Status

| Java | Rust | State |
| --- | --- | --- |
| `DBHandle(File)` open, `getDatabaseId`, `getTables`, `getTable` | `Database::open`, `database_id`, `tables`, `table` | read path done |
| `MasterTable` (iterate master rows, table list) | `Database::open`, `table_records` | done |
| `TableRecord` incl. `forceUseOfVariableLengthKeyNodesIfNeeded` | `TableRecord` | done |
| `Table.iterator`, `getRecord`, `getRecordCount`, `getMaxKey` | `Table::records`, `get`, `record_count`, `max_key` | done |
| `FieldIndexTable` read (`findPrimaryKeys`) | `Table::index_entries`, `find_primary_keys` | done (scan, not range seek) |
| `DBHandle(int)` create, `createTable` | `Database::create`, `create_table` | done for long-key tables |
| `Table.putRecord`, `deleteRecord` (long, fixed-length and variable-length keys) | `put_record`, `delete_record`, `delete_record_field` | done, with index maintenance in Java order (update: index first; insert: index after; delete: index first) |
| `endTransaction` / `saveAs` master flush | `commit`; `MemoryBufferStore::save_to_file` | done |
| field-key table writes (fixed-key 5-7, var-key 3-4), `FieldIndexTable.addEntry/deleteEntry`, `createTable` with index columns | `create_indexed_table`, `Tree` | done; byte-identical to Java on 16 scripts (see below) |
| `startTransaction`, `endTransaction` (commit and rollback), `terminateTransaction`, `checkTransaction`, `undo`, `redo`, `canUndo`, `canRedo`, `getAvailableUndoCount/RedoCount`, `setMaxUndos`, `hasUncommittedChanges`, `isChanged` (`cachedChangedState`), `getModCount`, `reloadTables`, `deleteTable`, `setTableName`, `saveAs(file, false)` | `Database<CheckpointStore>`: `start_transaction`, `end_transaction`, `terminate_transaction`, `undo`, `redo`, `can_undo`, `can_redo`, `available_undo_count`, `available_redo_count`, `set_max_undos`, `has_uncommitted_changes`, `is_changed`, `mod_count`, `delete_table`, `set_table_name`, `save_as` | done; byte-identical to Java on the scripts of `tests/tx_diff.rs` (see below) |
| `Table.isConsistent`, statistics, `RecordIterator` seek/bounds, `DBLongIterator`, a public `Table.deleteAll`, schema changes | none (`delete_all` exists inside `delete_table`) | NOT ported |

## Tests

`Framework/DB/src/test` table tests (`TableTest`, `DBTestUtils`, ...) all create tables, so
they need the write path and are not ported yet. The read path is checked by
`tests/oracle_diff.rs` against `oracle/OracleDb.java` output (`testdata/oracledb-*.txt`) on both
legacy fixtures: master rows (including the node family Java selects), per table the record count
and a SHA-256 over key bytes and record bytes. Rust decodes each record and re-encodes it, so a
match proves the Field and Schema encoders reproduce the file bytes. Also checked: every index
table equals the entries derived from its primary table (all columns), and `find_primary_keys`.

## Transactions, undo and redo: `tests/tx_diff.rs`

`oracle/OracleTx.java` runs a script on `DBHandle` and prints every observable: the result of each `end`, `undo`,
`redo` and `rename`, expected errors (`try`, with the exception class), `status` (undo and redo counts, `canUndo`,
`canRedo`, `uncommitted`, `changed`, `tx` and the free index stack in stack order, read by reflection) and, at every
`snap`, the output of `db.buffers.Oracle` and `db.OracleDb` on a file written with `saveAs(file, false)`. The Rust test
replays the script and builds the same transcript; for a snapshot it calls `Database::save_as`, reads the written file
back with `BufferFile` and `Database::open`, so the comparison is on the bytes Rust wrote. Every line must be equal:
buffer geometry, free list, SHA-256 of each buffer, master rows, table counts, status and the stack order.

Scripts (`oracle/gen_tx_scripts.py`; expected files by `oracle/run_tx.sh`; in `testdata/tx`): `tx-basic` (commit,
rollback, undo, redo, rename, deleteTable, terminate, errors outside a transaction, snapshots), `tx-many-commits` (40
transactions, packing, redo dropped by a new transaction, `maxundos 2`), `tx-delete-heavy` (three indexed tables with
chained records, deleteTable committed and rolled back, undo of the deletion) and six random sequences of 60 to 120
steps over four tables (long, int and string keys, fixed and variable records, 0 to 3 indexes, chained records) with 507,
1019, 2043 and 16379 byte buffers and `maxundos` 0, 1, 3 and 30. All 9 are byte-identical to Java.

Sweep: `oracle/gen_tx_scripts.py <dir> sweep` writes 24 more random scripts (100 steps, random `maxundos` 0 to 5);
`HYDRA_TX_SWEEP_DIR=<dir> cargo test -p ghidra-fmt-db --test tx_diff sweep -- --ignored` replays them. Java itself
fails one (tx-sweep-03: the file it saves has an unreadable chained buffer after `maxundos 0`; a Java problem). Of the
other 23, 20 are byte-identical and 3 differ: tx-sweep-00 and tx-sweep-15 (both contain `maxundos 0`, where Java keeps
an unreachable checkpoint list; sweep-00 ends with a different index count) and tx-sweep-18 (a node created after a
rollback holds 3 stale bytes in Java where Rust zero fills; delta debugging reduced it to `maxundos 1`, one committed
transaction, one rolled back transaction that creates and deletes tables, and one more transaction; the cause in
`BufferMgr` was not found). Those three are read-compatible, not byte-identical.

Behaviour with `CheckpointStore`:

* identical to Java: the result of every transaction call, the errors, the counters, the free stack order and every
  buffer byte for commit, rollback, undo, redo, packing, `setMaxUndos`, `deleteTable`, `setTableName` and `saveAs`;
* `setTableName` only marks the master row dirty. `endTransaction` flushes master rows only when a buffer changed, so a
  transaction that only renames adds no checkpoint (`end added=false`) and the row is written by the next flush; `saveAs`
  flushes it in a hidden transaction and undoes that, which reads the old name back (kept, and covered by `tx-basic`);
* read-compatible only: the three sweep scripts above, and any run that exhausts Java's 4 MiB cache;
* `Database<MemoryBufferStore>` has no transactions (`commit` is the master flush, as before).

## Kept from Java

* The node family is chosen by the schema, with the legacy var-key override from the root buffer's
  node type byte.
* The master table is always a long-key variable-length table rooted at DBParms parameter 0.
* Index tables are looked up by name plus indexed column, in master order.

## Differences

* `Database` owns an immutable store; there is no recovery file or buffer cache.
* `find_primary_keys` scans the index table instead of seeking; same result, O(n).
* An empty-name or duplicate-name primary table is not rejected (Java keeps the last).

## Write path and its differential test

`tests/build_diff.rs` replays the scripts in `testdata/build/*.script` (generated by
`oracle/gen_build_scripts.py`) with `oracle/OracleBuild.java` (repository DB classes: `DBHandle`,
`createTable`, `putRecord`, `deleteRecord`, `endTransaction`, `saveAs`) and compares every buffer
of the result with the Rust database built from the same script: buffer count, free list, and the
SHA-256 of every buffer (the expected outputs are the `.expected` files, produced by
`db.buffers.Oracle` + `db.OracleDb` on the Java-saved file). Scripts: sequential, reverse and
random inserts, random updates with growing and shrinking records (chained buffers), random
deletes down to an empty table and refill (leaf removal, interior merge, buffer reuse), fixed
length records, three tables with periodic commits and a table created mid-way, and the default
16 KiB buffer size. All seven match byte for byte. The saved Rust files were also read back by
the Java oracle (`db.OracleDb` and `db.buffers.Oracle`, with `HYDRA_FMT_KEEP_DIR` set to keep
them): table list, record counts, record hashes, consistency and per-buffer hashes are identical
to the Java-built file.

## Quirks kept

* The database id is a parameter of `Database::create` (Java draws it from
  `UniversalIdGenerator`); the test passes the id Java used.
* `MasterTable.flush` rewrites the master row of every table whose record is dirty; rows are
  fixed length so rewriting all of them gives the same bytes.
* Table creation writes the master row immediately (so the master root exists after the first
  `create_table`) and stores the new master root in parameter 0; `commit` does not touch the
  parameter in Java (it cannot change there), the port refreshes it if it ever did.

## Field-key and index writes (stage 5)

`ghidra-fmt-btree::keywrite` serves the long-key and fixed-key families (one implementation, the key is 8 bytes
compared as a long or `keySize` bytes compared as a field), `varwrite` the var-key family. `varwrite` keeps the
per-operation node cache with `parent` links because `VarKeyInteriorNode.keyChanged` can split a node and `split`
repairs links by hand; `getRoot()` follows them.

Tests: `tests/build_ix_diff.rs` replays the scripts of `oracle/OracleBuildIx.java` (generated by `oracle/GenIx.java`,
expected output from `oracle/run_ix.sh`): fixed-key int/short tables, string-key tables with fixed and variable
records (indirect records included), long and int tables with one, two (created out of order) and three indexes,
indexes on string columns (var-key index nodes), two stress runs of 3000 operations with 40 to 45 percent deletes.
Every buffer SHA-256, the free list, the master rows and the table counts match Java, and Java (`OracleDb` incl.
`isConsistent`) reads the files Rust saved identically.

Field-key tail (transactions round). The index iteration order of `Table.indexedColumns` is `IntObjectHashtable.getKeys`
order: `column % 37` (the initial capacity `Prime.nextPrime(3)` is 17 and `IntKeyIndexer` rounds that up to the next
prime, 37), newest key first inside one hash list. The earlier model (`% 13`, creation order) agreed only for columns 0
to 2. New scripts, all byte-identical to Java: `ix-wide-order` (a 40 column table indexed on 1, 38, 13, 14, 0, 39, 25,
where 1 and 38 share a hash list) and `ix-wide-two-tables`, both of which fail with the old order; `ix-sparse` (long and
int key tables with indexes on sparse String and Int columns; `FieldIndexTable` skips null values); `ix-binary-column`
(index on a Binary column with values up to 29 bytes; Java asserts above 54 bytes, and a string key table cannot have
indexes at all: "variable length primaryKey not supported"). The sparse tables exposed one Java quirk, now reproduced:
`Table.updatedRecord` compares columns with `Field.equals`, which finds an absent (null state) integer equal to an
explicit zero, so an update between the two leaves a stale or missing index entry (`same_column`). The index of a sparse
column is therefore compared with Java but not with its primary table.

Still not covered: legacy index fields (`LegacyIndexField`) and `forceUseOfVariableLengthKeyNodes` tables cannot be
created; `Table.isConsistent`, statistics and iterator seek/bounds are not ported.
