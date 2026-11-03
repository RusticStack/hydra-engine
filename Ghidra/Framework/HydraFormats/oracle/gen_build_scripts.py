"""Generates the deterministic build scripts in testdata/build (see OracleBuild.java).

Run: python gen_build_scripts.py <output dir>
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


def blob(rng, n):
    return "-" if n == 0 else "".join("%02x" % rng.below(256) for _ in range(n))


def put_var(name, key, rng, maxlen):
    n = rng.below(maxlen + 1)
    return "put %s %d %d %s" % (name, key, rng.below(2000000) - 1000000, blob(rng, n))


def put_fixed(name, key, rng):
    return "put %s %d %d %d %d" % (
        name,
        key,
        rng.next() - (1 << 63) if rng.below(2) else rng.below(1000),
        rng.below(2000000) - 1000000,
        rng.below(60000) - 30000,
    )


def seq():
    r = Rng(1)
    out = ["buffer 507", "table V var"]
    for i in range(1500):
        out.append(put_var("V", i, r, 150 if i % 97 == 0 else 50))
    return out


def reverse():
    r = Rng(2)
    out = ["buffer 507", "table V var"]
    for i in range(800, -1, -1):
        out.append(put_var("V", i, r, 60))
    return out


def rand():
    r = Rng(3)
    out = ["buffer 507", "table V var"]
    special = [-(1 << 63), (1 << 63) - 1, 0, -1, 1]
    for i in range(3500):
        k = special[r.below(5)] if r.below(40) == 0 else r.below(900) - 300
        if r.below(10) < 7:
            out.append(put_var("V", k, r, 300 if r.below(8) == 0 else 70))
        else:
            out.append("del V %d" % k)
    return out


def drain():
    r = Rng(4)
    out = ["buffer 507", "table V var"]
    keys = list(range(700))
    for k in keys:
        out.append(put_var("V", k, r, 80))
    order = keys[:]
    for i in range(len(order) - 1, 0, -1):
        j = r.below(i + 1)
        order[i], order[j] = order[j], order[i]
    for k in order:
        out.append("del V %d" % k)
    for k in range(60):
        out.append(put_var("V", k * 3, r, 80))
    return out


def fixed():
    r = Rng(5)
    out = ["buffer 507", "table F fixed"]
    for i in range(2500):
        k = r.below(700) - 100
        if r.below(10) < 7:
            out.append(put_fixed("F", k, r))
        else:
            out.append("del F %d" % k)
    return out


def multi():
    r = Rng(6)
    out = ["buffer 507", "table A var", "table B fixed"]
    for i in range(3000):
        if i == 1000:
            out.append("table C var")
        if i % 200 == 199:
            out.append("commit")
        t = r.below(3 if i >= 1000 else 2)
        k = r.below(500)
        if r.below(10) < 7:
            if t == 1:
                out.append(put_fixed("B", k, r))
            else:
                out.append(put_var("AC"[t // 2], k, r, 130))
        else:
            out.append("del %s %d" % ("ABC"[t], k))
    return out


def default16k():
    r = Rng(7)
    out = ["buffer 16379", "table V var", "table F fixed"]
    for i in range(1200):
        k = r.below(1000)
        if r.below(10) < 8:
            out.append(put_var("V", k, r, 4000 if r.below(30) == 0 else 90))
            if i % 3 == 0:
                out.append(put_fixed("F", k, r))
        else:
            out.append("del V %d" % k)
    return out


def main():
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    for name, fn in [
        ("seq", seq),
        ("reverse", reverse),
        ("rand", rand),
        ("drain", drain),
        ("fixed", fixed),
        ("multi", multi),
        ("default16k", default16k),
    ]:
        with open(os.path.join(d, name + ".script"), "w", newline="\n") as f:
            f.write("\n".join(fn()) + "\n")


main()
