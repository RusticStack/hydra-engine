# ghidra-fmt-pack porting notes

Source: `ghidra.framework.store.local.ItemSerializer` (format) and `ItemDeserializer` (reader), as
used by `PackedDatabase` for `.pdb` files. Read path only.

## Format

1. `ObjectOutputStream` header `AC ED 00 05`, then block-data records (`0x77` + 1-byte length, or
   `0x7a` + 4-byte length; at most 1024 bytes per record). Concatenated, the payload is: long magic
   `0x2e30212634e92c20`, int version 1, UTF item name, UTF content type (blank = none), int file
   type, long content length. Values may straddle record boundaries (the reader treats the records
   as one byte stream) and the last record ends exactly where the ZIP starts.
2. ZIP stream: one local entry named `FOLDER_ITEM`, method deflate. `ZipOutputStream` sets flag bit 3,
   so sizes and CRC follow the compressed data in a data descriptor (with or without its signature).

## Tests

Java has `PackedDatabaseTest` (needs a running database and a Ghidra test harness); nothing ports
one-to-one. Instead `testdata/pack/*.pdb` were produced by `ItemSerializer` through
`oracle/PackOracle.java` and unpacked again by `ItemDeserializer` (round trip checked equal in Java):

* `legacy.pdb`: the legacy-12.1.4 `db.1.gbf` (dynamic Huffman); Rust output equals the source file
  byte for byte and opens as a database (`tests/legacy_pdb.rs`).
* `text.pdb` (dynamic or fixed Huffman), `short.pdb` (blank content type), `rnd.pdb` (random bytes,
  stored block).
* Hand-built files cover header values straddling several block-data records, blank name, bad
  entry name, CRC mismatch and the compression-ratio guard; every truncation of a real file
  returns an error.

## Kept from Java

* Compression-ratio guard (`length / fileLen > 130` is refused), blank name or `length <= 0` refused.
* Content length from the header is authoritative: more data is an error.
* Magic detection at byte offset 6 (`isPackedFile`).

## Differences

* No `java.util.zip`: `inflate.rs` is a small RFC 1951 decoder, and the CRC-32 and sizes of the
  data descriptor are verified (as `ZipInputStream` does).
* Less data than the header length is an error (Java copies what exists, then the caller fails
  later on a short database).
* ZIP64, multiple entries, other methods and encryption are refused.
* Write side (`outputItem`) is not ported; only the reader exists.
