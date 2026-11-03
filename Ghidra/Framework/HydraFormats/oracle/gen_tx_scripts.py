"""Generates the deterministic transaction scripts in testdata/tx (see OracleTx.java).

Run: python gen_tx_scripts.py <output dir>
Then: run_tx.sh <classes dir> <classpath file> <output dir> NAME...  for the .expected files.
"""
import os
import sys


class Rng:
    """xorshift64*, so the scripts do not depend on the Python version."""

    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFFFFFFFFFF

    def next(self):
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF

    def below(self, n):
        return (self.next() >> 11) % n


# name -> (key kind, layout, indexed columns); the renamed names R0..R3 reuse these
SPECS = {
    "T0": ("long", "fixed", "1"),
    "T1": ("long", "var", "0,2"),
    "T2": ("string", "var", "-"),
    "T3": ("int", "fixed", "0,1,2"),
}
WORDS = ["alpha", "beta", "gamma", "delta", "eps", "zeta", "eta", "theta", "iota", "kappa"]


def spec_of(name):
    return SPECS["T" + name[1:]]


def key_of(rng, kind):
    n = rng.below(40)
    return "k%02d" % n if kind == "string" else str(n)


def put(rng, name):
    kind, layout, _ = spec_of(name)
    key = key_of(rng, kind)
    if layout == "fixed":
        return "put %s %s %d %d %d" % (
            name,
            key,
            rng.below(6) * 1000,
            rng.below(5) - 2,
            rng.below(4),
        )
    n = rng.below(4)
    size = 0 if n == 0 else (rng.below(40) if n < 3 else rng.below(900))
    blob = "-" if size == 0 else "".join("%02x" % rng.below(256) for _ in range(size))
    text = "-" if rng.below(6) == 0 else WORDS[rng.below(len(WORDS))]
    return "put %s %s %d %s %s" % (name, key, rng.below(5), blob, text)


def table(name):
    kind, layout, idx = spec_of(name)
    return "table %s %s %s %s" % (name, kind, layout, idx)


def random_script(seed, buffer, steps, max_undos=None, cache=None, fill=30, per_tx=14):
    """cache: memory cache size in bytes (64 KiB is the smallest Java accepts), so that the
    cache is exhausted and Java recycles buffers; fill: records put in the first transaction."""
    r = Rng(seed)
    out = ["buffer %d%s" % (buffer, "" if cache is None else " %d" % cache)]
    if max_undos is not None:
        out.append("maxundos %d" % max_undos)
    out.append("status")
    out.append("begin")
    for n in ("T0", "T1", "T2", "T3"):
        out.append(table(n))
    for _ in range(fill):
        out.append(put(r, "T" + str(r.below(4))))
    out += ["end commit", "status"]
    names = ["T0", "T1", "T2", "T3", "R0", "R1", "R2", "R3"]
    for _ in range(steps):
        a = r.below(100)
        if a < 62:
            out.append("begin")
            for _ in range(1 + r.below(per_tx)):
                b = r.below(100)
                nm = names[r.below(8)]
                if b < 66:
                    out.append(put(r, nm))
                elif b < 80:
                    out.append("del %s %s" % (nm, key_of(r, spec_of(nm)[0])))
                elif b < 86:
                    out.append("try " + table("T" + str(r.below(4))))
                elif b < 92:
                    out.append("deltable " + nm)
                elif b < 96:
                    i = r.below(4)
                    out.append("try rename %s %s" % (names[i] if r.below(2) else names[i + 4],
                                                     names[i + 4] if r.below(2) else names[i]))
                else:
                    out.append("status")
            out.append("end rollback" if r.below(5) == 0 else "end commit")
            out.append("status")
        elif a < 74:
            out += ["undo", "status"]
        elif a < 84:
            out += ["redo", "status"]
        elif a < 94:
            out.append("snap s%d" % len(out))
        elif a < 97:
            out.append("maxundos %d" % r.below(6))
        else:
            out += ["try put T0 1 1 1 1", "try end commit", "try begin", "try begin", "end rollback"]
    out.append("snap final")
    return out


def basic():
    return """buffer 507
status
snap empty
begin
table A long fixed 1
put A 1 5 6 7
put A 2 5 6 7
try begin
status
end commit
status
try put A 3 1 1 1
try end commit
try end rollback
begin
put A 3 1 1 1
del A 1
status
end rollback
status
snap after-rollback
begin
put A 9 9 9 9
end commit
undo
status
snap after-undo
redo
status
try rename A B
begin
rename A B
try rename A Z
try rename B B
rename B C
status
end commit
status
snap after-rename
begin
deltable C
status
end commit
status
snap after-deltable
undo
snap undo-deltable
undo
snap undo-rename
undo
undo
undo
status
redo
redo
redo
redo
status
snap redone
begin
terminate commit
try put C 1 1 1 1
begin
try put C 1 1 1 1
terminate rollback
try put C 1 1 1 1
try end commit
begin
try put C 1 1 1 1
end commit
status
snap final""".split("\n")


def many_commits():
    """More transactions than the default undo depth, with varying write sizes."""
    r = Rng(77)
    out = ["buffer 507", "begin", table("T1"), table("T0"), "end commit"]
    for i in range(40):
        out.append("begin")
        for _ in range(5 + r.below(10)):
            out.append(put(r, "T1" if r.below(3) else "T0"))
        out.append("end commit")
        if i % 7 == 6:
            out.append("snap c%d" % i)
        out.append("status")
    out += ["undo"] * 14
    out += ["status", "snap deep-undo"]
    out += ["redo"] * 5 + ["status", "snap redo5"]
    out += ["begin", put(r, "T1"), "end commit", "status", "snap redo-dropped"]
    out += ["maxundos 2", "begin", put(r, "T0"), "end commit", "status", "snap max2"]
    out += ["undo", "undo", "undo", "status", "snap final"]
    return out


def delete_heavy():
    """Fill tables with chained records, then delete tables and undo the deletion."""
    r = Rng(5)
    out = ["buffer 507", "begin", table("T1"), table("T2"), table("T3"), "end commit"]
    for _ in range(3):
        out.append("begin")
        for _ in range(60):
            out.append(put(r, "T1"))
            out.append(put(r, "T2"))
            out.append(put(r, "T3"))
        out.append("end commit")
    out += ["snap filled", "begin", "deltable T1", "end commit", "snap del-T1"]
    out += ["begin", "deltable T3", "deltable T2", "end rollback", "snap rolled-back"]
    out += ["begin", "deltable T3", "deltable T2", "end commit", "snap del-all"]
    out += ["begin", table("T0"), put(r, "T0"), "end commit", "snap new-table"]
    out += ["undo", "undo", "snap undo2", "undo", "snap undo3", "redo", "redo", "redo",
            "snap redo3", "status"]
    return out


SCRIPTS = {
    "tx-basic": basic(),
    "tx-many-commits": many_commits(),
    "tx-delete-heavy": delete_heavy(),
    "tx-rand-1": random_script(11, 507, 60),
    "tx-rand-2": random_script(12, 507, 80, 3),
    "tx-rand-3": random_script(13, 1019, 70, 0),
    "tx-rand-4": random_script(14, 16379, 70),
    "tx-rand-5": random_script(15, 507, 120, 30),
    "tx-rand-6": random_script(16, 2043, 80, 1),
}
# the memory cache of the buffer manager is exhausted (64 KiB = 129 buffers of 507 bytes)
CACHE = {
    "tx-cache-1": random_script(21, 507, 40, None, 65536, 400, 30),
    "tx-cache-2": random_script(22, 507, 40, 3, 65536, 400, 30),
    "tx-cache-3": random_script(23, 1019, 40, 0, 65536, 300, 30),
    "tx-cache-4": random_script(24, 507, 40, 1, 65536, 400, 30),
    "tx-cache-5": random_script(25, 2043, 40, 30, 65536, 300, 30),
    "tx-cache-6": random_script(26, 2043, 40, None, 65536, 300, 30),
    "tx-cache-7": random_script(27, 4091, 40, 3, 65536, 200, 30),
    "tx-cache-8": random_script(28, 1019, 50, 2, 65536, 500, 30),
    "tx-cache-9": random_script(29, 2043, 60, 5, 65536, 300, 30),
}
SCRIPTS.update(CACHE)
# extra seeds used to measure how often a random script diverges (see PORTING.md)
SWEEP = {
    "tx-sweep-%02d" % i: random_script(100 + i, (507, 1019, 2043)[i % 3], 100, (None, 2, 5, 0, 12, 1)[i % 6])
    for i in range(24)
}

if __name__ == "__main__":
    os.makedirs(sys.argv[1], exist_ok=True)
    sweep = len(sys.argv) > 2 and sys.argv[2] == "sweep"
    for name, lines in (SWEEP if sweep else SCRIPTS).items():
        with open(os.path.join(sys.argv[1], name + ".script"), "w", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
    print(" ".join(SWEEP if sweep else SCRIPTS))
