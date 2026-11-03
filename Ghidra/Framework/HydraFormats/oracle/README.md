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
    java -cp "out;$CP" OracleProgram <ghidra install dir> <db.gbf> > testdata/oracleprog-<name>.txt

It opens the file with `OpenMode.IMMUTABLE` and prints the language, address spaces, memory blocks
with their parts, and every symbol row by id. Log lines (stderr) are dropped.
