#!/bin/sh
# Writes NAME.expected next to each NAME.script: the output of OracleTx, which runs the
# transaction script and prints the buffer / master table state of every snapshot.
# Usage: run_tx.sh <classes dir> <classpath file> <scripts dir> NAME...
OUT=$1; CP=$(cat "$2"); DIR=$3; shift 3
for n in "$@"; do
  java -cp "$OUT;$CP" db.OracleTx "$DIR/$n.script" > "$DIR/$n.expected" 2>"$DIR/$n.err" || { echo "FAILED $n"; cat "$DIR/$n.err" | head -20; exit 1; }
  rm -f "$DIR/$n.err"
done
