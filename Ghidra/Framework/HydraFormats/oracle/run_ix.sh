#!/bin/sh
# Builds each given field-key/index script with Java and writes NAME.expected next to it
# (the output of OracleBuildIx, db.buffers.Oracle and db.OracleDb, concatenated).
# Usage: run_ix.sh <classes dir> <classpath file> <scripts dir> NAME...
OUT=$1; CP=$(cat "$2"); DIR=$3; shift 3
for n in "$@"; do
  T=$(mktemp -d)
  java -cp "$OUT;$CP" db.OracleBuildIx "$DIR/$n.script" "$T/x.gbf" > "$DIR/$n.expected" 2>/dev/null || exit 1
  java -cp "$OUT;$CP" db.buffers.Oracle "$T/x.gbf" >> "$DIR/$n.expected" 2>/dev/null || exit 1
  java -cp "$OUT;$CP" db.OracleDb "$T/x.gbf" >> "$DIR/$n.expected" 2>/dev/null || exit 1
  rm -rf "$T"
done
