Java oracle for the HydraFormats differential tests. See `crates/ghidra-fmt-btree/PORTING.md`.
`Oracle.java` is not part of any Gradle module; it is compiled ad hoc with `javac -sourcepath`.

Files (none is part of a Gradle module; compile with `javac -sourcepath` over
`Framework/{DB,Generic,Utility,FileSystem,Docking}/src/main/java` and the log4j, commons-collections4
and commons-lang3 jars of a stock Ghidra install):

* `Oracle.java` (package `db.buffers`): buffer geometry, free list, per buffer SHA-256, tables.
* `OracleDb.java` (package `db`): master table rows and, per table including index tables, the
  record count and SHA-256 over key and record bytes; `Table.isConsistent`.
* `OracleBuild.java` (package `db`): builds a database from a script in `testdata/build` and saves it.
  `gen_build_scripts.py <dir>` regenerates the scripts. Usage per script:
  `java db.OracleBuild x.script out.gbf` (prints `dbid=`), then `java db.buffers.Oracle out.gbf`
  and `java db.OracleDb out.gbf`; the concatenation is `x.expected`.
* `OracleBuildIx.java` (package `db`): like `OracleBuild` for field-key tables and index tables; `GenIx.java`
  (`java GenIx.java <dir>`) writes its scripts and `run_ix.sh <classes> <cp file> <dir> NAME...` the `.expected` files.
* `OracleTx.java` (package `db`): transactions, rollback, undo, redo, `setMaxUndos`, `deleteTable`, `setTableName`,
  `saveAs` snapshots and expected errors (see `crates/ghidra-fmt-db/PORTING.md`). `gen_tx_scripts.py <dir> [sweep]`
  writes `testdata/tx/*.script` and `run_tx.sh <classes> <cp file> <dir> NAME...` the `.expected` files;
  `ORACLETX_KEEP=<dir>` keeps the snapshot files. Expected files are generated with
  `-Dhydra.db.sharedPages=false` (run_tx.sh does that). `buffer N CACHE` sets the memory cache size in bytes
  (`tx-cache-*` scripts use 65536); `cachedump` prints the buffer manager's cache. `OracleBuildIx` also has the `wide` (40 Int columns) and `sparse`
  layouts.
* `PackOracle.java` (default package): `pack`/`unpack` through `ItemSerializer`/`ItemDeserializer`
  for the `.pdb` fixtures in `testdata/pack`.

To check that Java reads what Rust wrote: `HYDRA_FMT_KEEP_DIR=<dir> cargo test -p ghidra-fmt-db
--test build_diff` leaves `rust-built-<name>.gbf` files in `<dir>`; run `db.OracleDb` and
`db.buffers.Oracle` on them and compare with the `.expected` files.

## Program database oracle

`OracleProgram.java` (default package) needs the stock Ghidra jars, because `ProgramDB` is not
built from this repository's sources here. Build the classpath from every jar under the stock
`Ghidra/Framework`, `Ghidra/Features/Base`, `Ghidra/Configurations` and `Ghidra/Processors/x86`
(not the `-src` ones), then:

    javac -cp "$CP" -d out OracleProgram.java
    java -cp "out;$CP" OracleProgram <ghidra install dir> <db.gbf> 2>/dev/null | grep -v -E "^(INFO|WARN|ERROR|DEBUG) " > testdata/oracleprog-<name>.txt

It opens the file with `OpenMode.IMMUTABLE` and prints the language, address spaces, memory blocks
with their parts, every symbol row by id, the listing, memory and symbol query sections, and the data types (categories, every stored type with kind, name, path, length and base, structure / union components, enum values, function definition parameters; defined data rows carry the resolved type path). Log lines (stderr) are dropped.

`OracleMutate.java` builds the synthetic fixture `testdata/synth/progdb-synth-33.gbf` (see
`crates/ghidra-progdb/PORTING.md`): `java -cp "mut;$CP" OracleMutate <install dir> <source db.1.gbf>
<scratch copy.gbf> <out.gbf>`; run `OracleProgram` on the result for `testdata/oracleprog-synth-33.txt`.

`OracleOpenBench.java` times `new DBHandle` + `new ProgramDB` and a few queries on stock Ghidra, the
counterpart of `crates/ghidra-progdb/examples/open_bench.rs`; peak memory is sampled from outside
(`Process.PeakWorkingSet64`). Use the real `java.exe` of the JDK, not the `javapath` shim, which
starts the JVM as a child process.
