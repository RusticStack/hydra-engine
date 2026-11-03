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
| transactions, undo/redo, `createTable`, `putRecord`, `deleteRecord`, save | none | NOT ported (write path, see below) |
| `Table.isConsistent`, statistics, `RecordIterator` seek/bounds, `DBLongIterator` | none | NOT ported |

## Tests

`Framework/DB/src/test` table tests (`TableTest`, `DBTestUtils`, ...) all create tables, so
they need the write path and are not ported yet. The read path is checked by
`tests/oracle_diff.rs` against `oracle/OracleDb.java` output (`testdata/oracledb-*.txt`) on both
legacy fixtures: master rows (including the node family Java selects), per table the record count
and a SHA-256 over key bytes and record bytes. Rust decodes each record and re-encodes it, so a
match proves the Field and Schema encoders reproduce the file bytes. Also checked: every index
table equals the entries derived from its primary table (all columns), and `find_primary_keys`.

## Kept from Java

* The node family is chosen by the schema, with the legacy var-key override from the root buffer's
  node type byte.
* The master table is always a long-key variable-length table rooted at DBParms parameter 0.
* Index tables are looked up by name plus indexed column, in master order.

## Differences

* `Database` owns an immutable store; there is no recovery file or buffer cache.
* `find_primary_keys` scans the index table instead of seeking; same result, O(n).
* An empty-name or duplicate-name primary table is not rejected (Java keeps the last).
