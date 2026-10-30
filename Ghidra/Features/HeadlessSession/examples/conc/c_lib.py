## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
"""Measurement C library: crash safety harness for the Hydra engine under test (``--ghidra``).

Kill = Win32 TerminateProcess on the daemon JVM pid (the call Stop-Process -Force makes).
Everything is written under the run root (``--work``; ``--refs-root`` for ReFS projects).
"""
import ctypes
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import sys
import threading
import time
from collections import Counter

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xc  # noqa: E402  (reads --ghidra --work --project --program --fixtures ... from argv)
from xc import gs  # noqa: E402
from ghidra_session import SessionError  # noqa: E402

INSTALL = xc.ENGINE
os.environ["X0_GHIDRA"] = INSTALL          # c_worker.py, a child process, reads it
RUN_ROOT = xc.ROOT
FIXTURE_DIR = xc.FIX_SRC / "fx-x64-flow" if xc.FIX_SRC else None


def _bases():
    """The two projects of the crash scenarios. ``fixture`` is the small public fixture program;
    ``large`` is the project given with --project/--program (its prepared copy: mkbase.py)."""
    b = {}
    if FIXTURE_DIR:
        gpr = next(FIXTURE_DIR.glob("*.gpr"))
        b["fixture"] = {"base": str(FIXTURE_DIR), "gpr": gpr.name, "prog": os.environ.get("X0_FIXTURE_PROGRAM", "/flow_fixture.exe"),
                        "M": 300, "S": 50}
    base = RUN_ROOT / "proj" / "base"
    if xc.BASE_GPR:
        b["large"] = {"base": str(base), "gpr": xc.BASE_GPR.name, "prog": xc.PROG, "M": 1500, "S": 50}
    return b


BASES = _bases()
IMPORT_EXE = xc.OPTS.fixture_exe or xc.IMPORT_EXE
REFS_ROOT = pathlib.Path(xc.OPTS.refs_root) if xc.OPTS.refs_root else None


def now():
    return time.perf_counter()


def ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


# ----------------------------------------------------------------------------- kill
_k = ctypes.windll.kernel32
_k.OpenProcess.restype = ctypes.c_void_p
_k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
_k.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
_k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
_k.CloseHandle.argtypes = [ctypes.c_void_p]


def terminate(pid, wait_s=120):
    """TerminateProcess (what Stop-Process -Force does) + wait for the process to be gone."""
    h = _k.OpenProcess(0x100001, 0, pid)  # PROCESS_TERMINATE | SYNCHRONIZE
    if not h:
        return {"terminated": False, "error": "OpenProcess failed"}
    t0 = now()
    ok = _k.TerminateProcess(h, 1)
    t_term = ms(t0)
    w = _k.WaitForSingleObject(h, int(wait_s * 1000))
    _k.CloseHandle(h)
    return {"terminated": bool(ok), "terminate_call_ms": t_term, "exit_wait_ms": ms(t0), "wait_result": w}


def sleep_precise(sec):
    if sec <= 0:
        return
    end = now() + sec
    if sec > 0.004:
        time.sleep(sec - 0.003)
    while now() < end:
        pass


# ----------------------------------------------------------------------------- hashing / inventory
def sha256_file(p, chunk=1 << 20):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def tree_hash(root):
    """Same definition as tools/golden.py tree_hash: sorted (relpath, size, sha256) of every file."""
    root = pathlib.Path(root)
    rows = []
    for directory, _n, files in os.walk(root):
        for name in files:
            p = pathlib.Path(directory, name)
            rows.append((p.relative_to(root).as_posix(), p.stat().st_size, sha256_file(p)))
    rows.sort()
    digest = hashlib.sha256("\n".join("%s\t%d\t%s" % r for r in rows).encode()).hexdigest()
    return {"files": len(rows), "bytes": sum(r[1] for r in rows), "tree_sha256": digest}


def inventory(root):
    """{relpath: size} for files and {relpath: None} for directories."""
    root = pathlib.Path(root)
    inv = {}
    if not root.exists():
        return inv
    for directory, dirs, files in os.walk(root):
        for d in dirs:
            inv[pathlib.Path(directory, d).relative_to(root).as_posix() + "/"] = None
        for f in files:
            p = pathlib.Path(directory, f)
            try:
                inv[p.relative_to(root).as_posix()] = p.stat().st_size
            except OSError:
                inv[p.relative_to(root).as_posix()] = -1
    return inv


def tag_file(rel):
    n = rel.rstrip("/").split("/")[-1]
    if n.endswith(".lock~"):
        return "lock~"
    if n.endswith(".lock"):
        return "lock"
    if ".fork-" in rel and rel.split("/")[0].startswith("."):
        return "fork_tmp"
    if ".fork-" in rel:
        return "fork_tmp"
    if n.endswith(".tmp"):
        return "tmp"
    if n.endswith(".bak"):
        return "bak"
    if n.startswith("~journal"):
        return "journal"
    if re.fullmatch(r"db\.\d+\.gbf", n):
        return "gbf_version"
    if n.endswith(".prp"):
        return "prp"
    if n.startswith("~index"):
        return "index"
    if n.endswith(".fork.json"):
        return "sidecar"
    return "other"


def inv_diff(before, after):
    added = sorted(k for k in after if k not in before)
    removed = sorted(k for k in before if k not in after)
    changed = sorted(k for k in after if k in before and before[k] != after[k] and after[k] is not None)
    tags = Counter(tag_file(k) for k in added)
    return {"added": added[:40], "n_added": len(added), "added_tags": dict(tags),
            "removed": removed[:40], "n_removed": len(removed), "changed": changed[:40], "n_changed": len(changed)}


def residue_tags(inv):
    """Stale-lock / orphan-temp candidates in an inventory."""
    out = {}
    for k in inv:
        t = tag_file(k)
        if t in ("lock", "lock~", "fork_tmp", "tmp", "journal"):
            out.setdefault(t, []).append(k)
    return out


# ----------------------------------------------------------------------------- daemon rig
class Rig:
    def __init__(self, root, instance="c", name="rig"):
        self.root = pathlib.Path(root)
        self.state = self.root / "state"
        self.tmp = self.root / "tmp"
        self.state.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text(json.dumps({"tmpdir": str(self.tmp)}))
        self.instance = instance
        self.daemon = gs.Daemon(INSTALL, str(self.state), instance)
        self.name = name
        self._wd = None

    @property
    def log(self):
        return self.state / (self.instance + ".log")

    def log_size(self):
        try:
            return self.log.stat().st_size
        except OSError:
            return 0

    def log_since(self, off, pat=r"WARN|ERROR|ecover|orrupt|xception|lock|Lock|stale|fail"):
        try:
            with open(self.log, "rb") as f:
                f.seek(off)
                txt = f.read().decode("utf-8", "replace")
        except OSError:
            return []
        rx = re.compile(pat)
        lines = [l.strip()[:300] for l in txt.splitlines() if rx.search(l)]
        # drop the routine per-request INFO lines
        return [l for l in lines if not re.match(r"INFO\s+client \d+ .* ms ok", l)][:25]

    def start(self, client="crash", harness="c-harness"):
        t0 = now()
        c = self.daemon.connect(client, harness)
        return c, ms(t0)

    def pid(self):
        ep = self.daemon.read_endpoint()
        return int(ep["pid"]) if ep and ep.get("pid") else None

    def kill(self):
        pid = self.pid()
        if not pid:
            return {"terminated": False, "error": "no pid"}
        try:  # K7 after every kill (kcheck.py): what was below the daemon at the kill must be gone after it
            import kcheck
            below = sorted(kcheck.O.descendants([pid]))
        except Exception:  # noqa: BLE001
            below = None
        r = terminate(pid)
        r["pid"] = pid
        r["descendants"] = below
        r["jvm_alive_after"] = self.daemon.jvm_alive()
        return r

    def stop(self, timeout=120):
        t0 = now()
        try:
            self.daemon.stop(force=True, timeout=timeout)
            return {"clean_stop_ms": ms(t0), "ok": not self.daemon.jvm_alive()}
        except Exception as e:  # noqa: BLE001
            return {"clean_stop_ms": ms(t0), "ok": False, "error": repr(e)[:200]}

    def watchdog(self, seconds):
        self.cancel_watchdog()

        def fire():
            pid = self.pid()
            if pid:
                terminate(pid, 10)
        self._wd = threading.Timer(seconds, fire)
        self._wd.daemon = True
        self._wd.start()

    def cancel_watchdog(self):
        if self._wd:
            self._wd.cancel()
            self._wd = None


def send_watch(c, cmd, **fields):
    """Sends a request, a thread records the outcome and the time it arrived."""
    res = {"t_send": now()}
    rid = c.send(cmd, **fields)

    def w():
        try:
            r = c.wait(rid)
            res["ok"] = True
            res["result"] = r
        except SessionError as e:
            res["ok"] = False
            res["code"] = e.code
            res["message"] = (e.message or "")[:300]
        except Exception as e:  # noqa: BLE001
            res["ok"] = False
            res["code"] = "py:" + type(e).__name__
        res["t_done"] = now()
    th = threading.Thread(target=w, daemon=True)
    th.start()
    return rid, res, th


def kill_during(rig, c, cmd, delay, **fields):
    """Send cmd, kill the daemon `delay` seconds later. Returns outcome info."""
    rid, res, th = send_watch(c, cmd, **fields)
    sleep_precise(delay - (now() - res["t_send"]))
    t_kill = now()
    kr = rig.kill()
    th.join(10)
    acked = bool(res.get("ok")) and res.get("t_done", 1e18) <= t_kill
    return {"delay_s": round(delay, 4), "acked_before_kill": acked,
            "answered_ok": bool(res.get("ok")), "answer_code": res.get("code"),
            "answer_ms_after_send": round((res["t_done"] - res["t_send"]) * 1000, 1) if "t_done" in res else None,
            "kill": kr}, res


# ----------------------------------------------------------------------------- program scanning
GEN_RX = re.compile(r"^c([a-z])g?(\d+)_(\d+)$")


def all_functions(c, key):
    out, off = [], 0
    while True:
        r = c.call("functions", program=key, offset=off, limit=10000)
        out.extend(r["functions"])
        if not r.get("truncated"):
            break
        off += r["returned"]
    return out


def parse_gen(name, prefix="cg"):
    m = re.search(prefix + r"(\d+)_(\d+)$", name)
    return int(m.group(1)) if m else 0


def scan_program(c, key, madrs, sample, deep=True, prefix="cg"):
    t0 = now()
    fl = all_functions(c, key)
    byaddr = {f["address"]: f["name"] for f in fl}
    names_sha = hashlib.sha256("\n".join("%s\t%s" % (a, n) for a, n in sorted(byaddr.items())).encode()).hexdigest()
    gens = Counter(parse_gen(byaddr.get(a, ""), prefix) if a in byaddr else -1 for a in madrs)
    r = {"functions": len(fl), "names_sha": names_sha, "gens": dict(gens)}
    if len(gens) == 1:
        r["state"] = "gen:%d" % next(iter(gens))
    else:
        r["state"] = "MIXED:" + json.dumps(dict(gens), sort_keys=True)
    if deep:
        dec, errs, name_in_c = {}, 0, 0
        for a in sample:
            try:
                d = c.call("decompile", program=key, address=a, timeout=60)
                dec[a] = hashlib.sha256((d.get("c") or "").encode()).hexdigest()[:16] if d.get("completed", True) else "INCOMPLETE"
                nm = byaddr.get(a, "").split("::")[-1]
                if nm and nm in (d.get("c") or ""):
                    name_in_c += 1
            except SessionError as e:
                dec[a] = "ERR:" + str(e.code)
                errs += 1
        r["decomp"] = dec
        r["decomp_errors"] = errs
        r["name_in_c"] = name_in_c
        r["n_sample"] = len(sample)
    r["scan_ms"] = ms(t0)
    return r


def digest(scan):
    """The comparable part of a scan."""
    d = {k: scan[k] for k in ("functions", "names_sha", "state") if k in scan}
    if "decomp" in scan:
        d["decomp"] = scan["decomp"]
    return d


def same(a, b):
    return a is not None and b is not None and digest(a) == digest(b)


def diff_scan(a, b):
    """What differs between a baseline scan and observed (short)."""
    out = {}
    for k in ("functions", "names_sha", "state"):
        if a.get(k) != b.get(k):
            out[k] = [a.get(k), b.get(k)]
    if "decomp" in a and "decomp" in b:
        out["decomp_diff"] = sum(1 for x in a["decomp"] if a["decomp"].get(x) != b["decomp"].get(x))
    return out


def inspect(c, gpr, writable, ctx, deep=True, prefix="cg", progs_filter=None):
    """Open the project, every program in it, scan it. Returns a dict (errors captured, never raised)."""
    r = {"writable": writable}
    t0 = now()
    try:
        o = c.call("open_project", path=str(gpr), writable=writable)
    except SessionError as e:
        r["open_project_error"] = [e.code, (e.message or "")[:300]]
        r["open_project_ms"] = ms(t0)
        return r
    r["open_project_ms"] = ms(t0)
    r["project_files"] = o.get("files")
    pid = o["id"]
    try:
        l = c.call("list", project=pid, programsOnly=True, recursive=True)
    except SessionError as e:
        r["list_error"] = [e.code, (e.message or "")[:300]]
        return r
    r["programs"] = {}
    for e in l["entries"]:
        path = e["path"]
        if progs_filter and path not in progs_filter:
            continue
        pr = {}
        t1 = now()
        try:
            p = c.call("open_program", path=path, project=pid, writable=False)
            pr["open_program_ms"] = ms(t1)
            pr["info_functions"] = p.get("functions")
            pr["analyzed"] = p.get("analyzed")
            key = p["key"]
            is_main = path == ctx["prog"]
            pr["scan"] = scan_program(c, key, ctx["M_addrs"] if is_main else [], ctx["S_addrs"] if is_main else [],
                                      deep=deep and is_main, prefix=prefix)
            if not is_main:
                pr["scan"].pop("state", None)
                pr["scan"]["gens"] = {}
                fl = all_functions(c, key)
                pr["fn_count"] = len(fl)
            try:
                c.call("close_program", program=key)
            except SessionError:
                pass
        except SessionError as ex:
            pr["error"] = [ex.code, (ex.message or "")[:300]]
        except Exception as ex:  # noqa: BLE001
            pr["error"] = ["py:" + type(ex).__name__, str(ex)[:300]]
        r["programs"][path] = pr
    return r


def main_scan(insp, ctx):
    p = (insp.get("programs") or {}).get(ctx["prog"]) or {}
    return p.get("scan")


# ----------------------------------------------------------------------------- ops builder
def build_ops(addrs, gen, prefix="cg"):
    ops = []
    for i, a in enumerate(addrs):
        ops.append({"op": "rename", "address": a, "name": "%s%d_%04d" % (prefix, gen, i)})
        ops.append({"op": "comment", "address": a, "type": "plate", "text": "%s%d" % (prefix, gen)})
    return ops


def pick_sample(c, key, m, s):
    """M evenly spaced function addresses (decompilable size), and S of them for decompile hashing."""
    fl = [f for f in all_functions(c, key) if not f.get("thunk") and not f.get("external") and 16 <= f.get("size", 0) <= 3000]
    fl.sort(key=lambda f: int(f["address"], 16))
    step = max(1, len(fl) // m)
    madrs = [f["address"] for f in fl[::step]][:m]
    sstep = max(1, len(madrs) // (s + 10))
    cand = madrs[::sstep][: s + 10]
    return madrs, cand


class Ctx(dict):
    pass


def load_ctx(proj, run_root):
    """Context (base paths, sample addresses) for a project kind; creates the sample file on first use."""
    b = dict(BASES[proj])
    sp = pathlib.Path(run_root) / ("sample-%s.json" % proj)
    if sp.exists():
        b.update(json.loads(sp.read_text()))
    return Ctx(b, kind=proj)


# ----------------------------------------------------------------------------- trigger-based kill
def _listing(path):
    try:
        return frozenset(os.listdir(path))
    except OSError:
        return frozenset()


def measure_trigger(c, cmd, watch, **fields):
    """Unkilled run: ms from the first change of `watch`'s listing to the answer (None if no change seen)."""
    init = _listing(watch)
    rid, res, th = send_watch(c, cmd, **fields)
    t_trig = None
    while "t_done" not in res and now() - res["t_send"] < 120:
        if t_trig is None and _listing(watch) != init:
            t_trig = now()
    th.join(120)
    if t_trig is None:
        return None
    return round((res["t_done"] - t_trig) * 1000, 2)


def kill_after_trigger(rig, c, cmd, watch, delay, **fields):
    """Send cmd; when `watch`'s directory listing first changes, kill the daemon `delay` s later."""
    init = _listing(watch)
    rid, res, th = send_watch(c, cmd, **fields)
    t_trig = None
    while "t_done" not in res and now() - res["t_send"] < 120:
        if _listing(watch) != init:
            t_trig = now()
            break
    if t_trig is not None:
        sleep_precise(delay - (now() - t_trig))
    t_kill = now()
    kr = rig.kill()
    th.join(10)
    acked = bool(res.get("ok")) and res.get("t_done", 1e18) <= t_kill
    return {"delay_s": round(delay, 5), "trigger_hit": t_trig is not None,
            "trigger_ms_after_send": round((t_trig - res["t_send"]) * 1000, 1) if t_trig else None,
            "acked_before_kill": acked, "answered_ok": bool(res.get("ok")), "answer_code": res.get("code"),
            "answer_ms_after_send": round((res["t_done"] - res["t_send"]) * 1000, 1) if "t_done" in res else None,
            "kill": kr}, res
