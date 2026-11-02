# ###
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
"""Round-4 multi-project agent workload: 16 agents on three real programs at once, plus a background import.

    python -I multiproj_bench.py run --engine <install> --label <name> --shape a|b --work <root> --out <dir>

Shape a: one daemon, one state root, the Cyberpunk 2077, KotOR and KotOR II projects open in it; the Empire at War
import+analysis runs in the same daemon while the agents read and decompile the other three.
Shape b: one daemon per project (separate state roots); the same 16 agents and the same background import.

Agents (all started together):
  cp-00..cp-05 (6 direct) and cp-hy (Hydralysis)  7 on Cyberpunk 2077, disjoint function ranges:
      3 function pages, ~40 decompiles (2 shared for cross-agent identity), 20 xref/byte script reads,
      an overlay rename+comment+decompile on their own function, a script; cp-hy does the same through
      Hydralysis queries and one rename+publish through the publish queue.
  kotor-00..kotor-05 (6 direct)                   reads, 10 shared (hot) + 15 own (fresh) decompiles, 8 script
      reads, 1 info, an overlay edit, and on 3 of them fork/edit/save/close with the fork kept for verification.
  k2-00..k2-02 (3 direct)                         1 info, a function page, 12 decompiles, 6 xref/byte reads, 2 scripts.
  eaw-import (background, not an agent)           RusticSetup + import+auto-analysis of StarWarsG.exe.

Measured per agent and per project: wall, functions processed, op p50/p99, protocol waits (waited/queue), lock and
admission waits, host pool figures, errors, crash/restart, tree CPU by family (java/decompile/python), peak/mean
private bytes, host load.  Identity: every decompile/read/page reply is hashed; the same project is used across
runs and engines, so keys must match.  Fork edits are reopened and checked; read-only project trees are hashed
before and after.

Windows only, standard library only (ctypes), Python 3.11+.

Semantic trace additions (12.3-hydra.6, WS-I "multi-project soak"):
  --trace-readers N   N > 0 adds, in the same daemon (shape a) or in the Cyberpunk daemon (shape b), one live capture
                      (`tracewriter`, session `live`, 200 events every 100 ms) and N analysis agents (`tracereader`,
                      N = 2 in the gate) that query it and two closed reference sessions (ref-a, ref-b) while the 16
                      agents and the Empire at War import run. They run until the 16 agents and the import are done.
                      The 16 agents' reply keys keep their digest; the closed-session trace replies have their own
                      (`trace_correctness`). Every trace reply keeps its `waited`/`queue` envelope markers in its row,
                      so `waited` replies, `foreignBlocked`, errors and the byte identity of the project trees are
                      judged over the trace requests too.
  --cpu-profile P     HYDRA_CPU_PROFILE for the daemons.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import math
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
WORK = Path("C:/dev-overflow/hydra-perf/multiproj")
JAVA = "C:/dev-overflow/jdk/jdk-25.0.5+8"
HY_SRC = Path("E:/Projects/Hydra/wt/hy-final/src")
HY_PYTHON = Path("D:/Projects/Hydra/RusticRE/.venv/Scripts/python.exe")
INSTANCE = "rusticre"
SAVE_REPLIES = bool(os.environ.get("MP_SAVE_REPLIES"))
VOLATILE = {"ms", "elapsedMs", "openMs", "waitedMs", "cached", "cache", "queue", "timing", "timings", "took_ms",
            "elapsed", "seq", "journalSeq", "revision", "projectRevision", "view_revision", "latest_editor",
            "generation", "working_copy", "overlay_id", "boot", "requestId", "id", "query_s", "script_s", "agent",
            "seconds", "chars", "t", "pid", "uptimeMs", "startedAt", "at", "lineage", "program", "engine"}

# ----------------------------------------------------------------------------------------------- process tree sampler
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


class PMCEX(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD)] + [
        (n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                       "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                                       "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]


K32 = ctypes.WinDLL("kernel32", use_last_error=True)
K32.CreateToolhelp32Snapshot.restype = wt.HANDLE
K32.OpenProcess.restype = wt.HANDLE
K32.Process32FirstW.argtypes = K32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
K32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4
K32.K32GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(PMCEX), wt.DWORD]
K32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
K32.CloseHandle.argtypes = [wt.HANDLE]
K32.GetSystemTimes.argtypes = [ctypes.POINTER(wt.FILETIME)] * 3
QUERY_LIMITED, VM_READ, STILL_ACTIVE = 0x1000, 0x0010, 259


def _ft(f) -> int:
    return (f.dwHighDateTime << 32) | f.dwLowDateTime


def snapshot() -> list[tuple[int, int, str]]:
    h = K32.CreateToolhelp32Snapshot(2, 0)
    out = []
    e = PROCESSENTRY32W()
    e.dwSize = ctypes.sizeof(e)
    try:
        ok = K32.Process32FirstW(h, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.th32ParentProcessID, e.szExeFile.lower()))
            ok = K32.Process32NextW(h, ctypes.byref(e))
    finally:
        K32.CloseHandle(h)
    return out


class Proc:
    def __init__(self, pid, name, handle):
        self.pid, self.name, self.h = pid, name, handle
        c, x, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
        K32.GetProcessTimes(handle, ctypes.byref(c), ctypes.byref(x), ctypes.byref(k), ctypes.byref(u))
        self.created = _ft(c)

    def cpu(self) -> float:
        c, x, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
        if not K32.GetProcessTimes(self.h, ctypes.byref(c), ctypes.byref(x), ctypes.byref(k), ctypes.byref(u)):
            return 0.0
        return (_ft(k) + _ft(u)) / 1e7

    def alive(self) -> bool:
        code = wt.DWORD()
        return bool(K32.GetExitCodeProcess(self.h, ctypes.byref(code))) and code.value == STILL_ACTIVE

    def private(self) -> int:
        m = PMCEX()
        m.cb = ctypes.sizeof(m)
        return m.PrivateUsage if K32.K32GetProcessMemoryInfo(self.h, ctypes.byref(m), m.cb) else 0


def category(p: Proc, own: int) -> str:
    if p.pid == own:
        return "bench"
    if p.name in ("java.exe", "javaw.exe"):
        return "java"
    if p.name == "decompile.exe":
        return "decompile"
    if p.name.startswith("python"):
        return "python"
    return "other"


class Sampler(threading.Thread):
    """This process, its descendants, the daemons and their descendants; private bytes every 250 ms."""
    def __init__(self, interval=0.25):
        super().__init__(daemon=True)
        self.own = os.getpid()
        self.interval = interval
        self.procs: dict[int, Proc] = {}
        self.roots = {self.own}
        self.samples = []
        self.stop_evt = threading.Event()
        self.lock = threading.Lock()
        self.scan()

    def add_root(self, pid):
        with self.lock:
            self.roots.add(int(pid))
        self.scan()

    def _open(self, pid, name):
        h = K32.OpenProcess(QUERY_LIMITED | VM_READ, False, pid) or K32.OpenProcess(QUERY_LIMITED, False, pid)
        return Proc(pid, name, h) if h else None

    def scan(self):
        with self.lock:
            snap = snapshot()
            names = {pid: name for pid, _, name in snap}
            for pid in list(self.roots):
                if pid not in self.procs and pid in names:
                    p = self._open(pid, names[pid])
                    if p:
                        self.procs[pid] = p
            changed = True
            while changed:
                changed = False
                for pid, ppid, name in snap:
                    if pid in self.procs or ppid not in self.procs:
                        continue
                    parent = self.procs[ppid]
                    p = self._open(pid, name)
                    if p is None:
                        continue
                    if p.created < parent.created:
                        K32.CloseHandle(p.h)
                        continue
                    self.procs[pid] = p
                    changed = True

    def sample(self):
        self.scan()
        by, detail = {}, []
        with self.lock:
            for p in self.procs.values():
                if p.alive():
                    c = category(p, self.own)
                    mb = p.private()
                    by[c] = by.get(c, 0) + mb
                    detail.append((p.name, p.pid, round(mb / 2**20, 1)))
        total = sum(v for k, v in by.items() if k != "bench")
        detail.sort(key=lambda d: -d[2])
        self.samples.append((time.perf_counter(), total, by, detail[:5]))

    def run(self):
        while not self.stop_evt.is_set():
            t0 = time.perf_counter()
            with contextlib.suppress(Exception):
                self.sample()
            self.stop_evt.wait(max(0.01, self.interval - (time.perf_counter() - t0)))

    def cpu(self) -> dict:
        self.scan()
        by, counts = {}, {}
        with self.lock:
            for p in self.procs.values():
                c = category(p, self.own)
                by[c] = by.get(c, 0.0) + p.cpu()
                counts[c] = counts.get(c, 0) + 1
        return {"by": by, "processes": counts}

    def memory(self, t0, t1) -> dict:
        win = [s for s in self.samples if t0 <= s[0] <= t1]
        if not win:
            return {"samples": 0}
        peak = max(win, key=lambda s: s[1])
        return {"samples": len(win), "peak_mb": round(peak[1] / 2**20, 1),
                "mean_mb": round(statistics.mean(s[1] for s in win) / 2**20, 1),
                "peak_by_mb": {k: round(v / 2**20, 1) for k, v in peak[2].items()},
                "peak_java_mb": round(max(s[2].get("java", 0) for s in win) / 2**20, 1),
                "peak_detail": peak[3]}


def cpu_delta(a: dict, b: dict) -> dict:
    keys = set(a["by"]) | set(b["by"])
    d = {k: round(b["by"].get(k, 0.0) - a["by"].get(k, 0.0), 2) for k in sorted(keys)}
    d["total"] = round(sum(v for k, v in d.items() if k != "bench"), 2)
    return d


class LoadMon(threading.Thread):
    def __init__(self, interval=1.0):
        super().__init__(daemon=True)
        self.interval, self.stop_evt = interval, threading.Event()
        self.samples = []
        i, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
        K32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
        self.last = (_ft(i), _ft(k), _ft(u))
        self.tw = time.time()

    def run(self):
        while not self.stop_evt.is_set():
            self.stop_evt.wait(self.interval)
            i, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
            K32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
            tw1, now = time.time(), (_ft(i), _ft(k), _ft(u))
            wall = max(0.001, tw1 - self.tw)
            busy = ((now[1] - self.last[1]) + (now[2] - self.last[2]) - (now[0] - self.last[0])) / 1e7 / wall
            self.samples.append((tw1, max(0.0, busy)))
            self.last, self.tw = now, tw1

    def window(self, t0, t1) -> dict:
        xs = [b for (t, b) in self.samples if t0 <= t <= t1]
        if not xs:
            return {"samples": 0}
        return {"samples": len(xs), "mean_busy_cores": round(statistics.mean(xs), 2),
                "max_busy_cores": round(max(xs), 2), "min_busy_cores": round(min(xs), 2)}


# ----------------------------------------------------------------------------------------------- helpers
def strip(obj):
    if isinstance(obj, dict):
        return {k: strip(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [strip(v) for v in obj]
    return obj


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(strip(obj), sort_keys=True, default=str).encode()).hexdigest()[:24]


def write_json(path, obj):
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, math.ceil(q * len(xs)) - 1))] if xs else None


def strided(xs, n, offset=0):
    if not xs:
        return []
    step = max(1, len(xs) // max(1, n))
    seen, out = set(), []
    for i in range(n):
        j = (offset + i * step) % len(xs)
        if j in seen:
            continue
        seen.add(j)
        out.append(xs[j])
    return out


def decomp_hash(r):
    return {k: r.get(k) for k in ("name", "entry", "completed", "signature", "c", "truncated", "error")} if isinstance(r, dict) else r


LAST_ENV: dict = {}


def ecall(c, cmd, **fields):
    """One request whose envelope markers (waited/queue/ms) are kept for the row (single-agent process)."""
    LAST_ENV.clear()
    raw = c.call_raw(cmd, **fields)
    for k in ("waited", "queue", "ms", "stale", "refreshed"):
        if raw.get(k) is not None:
            LAST_ENV[k] = raw.get(k)
    return raw.get("result")


class Rows:
    """One JSON line per op, plus raw records."""
    def __init__(self, path, agent, project):
        self.f = open(path, "a", encoding="utf-8", buffering=1)
        self.agent, self.project = agent, project

    def raw(self, rec):
        rec = dict(rec)
        rec.setdefault("agent", self.agent)
        rec.setdefault("project", self.project)
        rec.setdefault("t", time.time())
        self.f.write(json.dumps(rec, default=str) + "\n")

    def op(self, name, fn, key=None, hashit=None, tkey=None):
        t0 = time.perf_counter()
        LAST_ENV.clear()
        rec = {"agent": self.agent, "project": self.project, "op": name, "t": time.time()}
        try:
            r = fn()
            rec["ok"] = True
            if isinstance(r, dict):
                for k in ("waited", "queue", "cached", "lane", "laneNote", "importSeconds", "analysis", "applied",
                          "unsaved", "changed", "imported"):
                    if k in r:
                        rec[k] = strip(r[k]) if not isinstance(r[k], (int, float, str, bool, type(None))) else r[k]
                if "ms" in r:
                    rec["srv_ms"] = r["ms"]
            if LAST_ENV:
                rec["waited"] = LAST_ENV.get("waited")
                rec["queue"] = LAST_ENV.get("queue")
                rec["env_ms"] = LAST_ENV.get("ms")
                if LAST_ENV.get("stale") is not None:
                    rec["stale"] = LAST_ENV.get("stale")
            if key is not None:
                rec["key"] = key
                rec["sha"] = digest(hashit(r) if hashit else r)
            if tkey is not None:        # a trace reply of a closed reference session: its own digest
                rec["tkey"] = tkey
                rec["tsha"] = digest(hashit(r) if hashit else r)
            return r
        except Exception as ex:  # noqa: BLE001 - counted
            rec["ok"] = False
            rec["code"] = getattr(ex, "code", None) or type(ex).__name__
            rec["msg"] = str(ex)[:300]
            d = getattr(ex, "details", None)
            if isinstance(d, dict):
                rec["details"] = {k: d.get(k) for k in
                                  ("reason", "waiters", "holder", "waitedMs", "phase", "code", "retryAfterMs")
                                  if k in d}
            if key is not None:
                rec["key"] = key
                rec["sha"] = "ERR:" + str(rec["code"])
            if tkey is not None:
                rec["tkey"] = tkey
                rec["tsha"] = "ERR:" + str(rec["code"])
            return None
        finally:
            rec["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            self.f.write(json.dumps(rec, default=str) + "\n")


def load_gs(install):
    os.environ["GHIDRA_SESSION_JAVA_HOME"] = JAVA
    sys.path.insert(0, str(Path(install) / "Ghidra/Features/HeadlessSession/support"))
    import ghidra_session as gs  # noqa: E402
    return gs


def tree_hash(root: Path, skip=("*.lock", ".lock")):
    root = Path(root)
    h = hashlib.sha256()
    files = 0
    total = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.endswith(".lock") or name.endswith(".tmp") or name.endswith(".log"):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        h.update(rel.encode() + b"\0")
        with open(p, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
        files += 1
        total += p.stat().st_size
    return {"sha256": h.hexdigest(), "files": files, "bytes": total}


def state_pid(state: Path):
    p = Path(state) / (INSTANCE + ".json")
    with contextlib.suppress(OSError, ValueError):
        return int(json.loads(p.read_text(encoding="utf-8"))["pid"])
    return None


def _pid_alive(pid: int) -> bool:
    out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"],
                         capture_output=True).stdout.decode("utf-8", "replace")
    return ('"%d"' % pid) in out


def spawn_child(args, log, python=None):
    lf = open(log, "ab")
    env = dict(os.environ)
    env["GHIDRA_SESSION_JAVA_HOME"] = JAVA
    return subprocess.Popen([str(python or sys.executable), "-I", str(Path(__file__)), *args], stdout=lf,
                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env), lf


# ----------------------------------------------------------------------------------------------- trace load
REF_EVENTS = 1500
LIVE = "live"


def trace_event(i, source="bench", variant=0, strings=True):
    """A deterministic TRACE-1 envelope: a mix of resource opens, state writes and app ticks."""
    k = i % 5
    if k in (0, 1):
        kind, payload = "core.resource.open", {"type": "file", "key": "res/%d" % (i % 37)}
        if strings and i % 10 == 0:
            payload["path"] = {"$string": "C:\\bench\\data\\file-%d.bin" % (i % 37)}
    elif k in (2, 3):
        new = i % 100
        if variant and i % 20 == 7:
            new += 1000                       # the reference variant differs at a few writes
        kind, payload = "core.state.write", {"object": i % 16, "key": "hp", "new": new}
    else:
        kind, payload = "app.tick", {"frame": i // 5}
    return {"kind": kind, "source_id": source, "source_seq": i, "producer_gen": 1, "clock_domain": "mono",
            "t_mono_ns": 1000 + i * 1000, "confidence": "exact", "process_id": 7, "thread_id": 1 + i % 4,
            "payload": payload}


def trace_connect(spec, name):
    gs = load_gs(spec["engine"])
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    return d.connect(name, "multiproj-trace", start=False, timeout=60)


def seed_reference_sessions(engine, state):
    """Writes ref-a and ref-b (closed) through the protocol; returns their sizes and a write event id.

    The reference sessions carry no `$string` values: a string becomes a keyed id (HMAC under a per-store random key,
    PROTOCOL-3.md / TRACE-1 section 11), which differs between two daemons by design, so a reply that holds one cannot
    be part of a cross-run digest. The live session does carry strings (it is timed, not hashed)."""
    gs = load_gs(engine)
    d = gs.Daemon(engine, str(state), INSTANCE)
    c = d.connect("multiproj-trace-seed", "multiproj-trace", start=False, timeout=60)
    out = {}
    try:
        for name, variant in (("ref-a", 0), ("ref-b", 1)):
            o = c.trace_open(name, create=True)
            cap = o["lease"]["cap"]
            for first in range(0, REF_EVENTS, 250):
                c.trace_append(name, cap, [trace_event(i, variant=variant, strings=False)
                                           for i in range(first, min(REF_EVENTS, first + 250))])
            c.trace_close(name, cap)
            q = c.trace_query(name, kinds=["core.state.write"], limit=3)
            out[name] = {"events": REF_EVENTS, "write_event": q["rows"][0]["event_id"] if q.get("rows") else None}
    finally:
        c.close()
    return out


def cmd_tracewriter(spec_path):
    """One live capture: appends batches to the session `live` until the stop file appears."""
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    rows = Rows(spec["rows"], spec["name"], "trace")
    c = rows.op("trace_connect", lambda: trace_connect(spec, spec["name"]))
    if c is None:
        return 1
    stop = Path(spec["stop"])
    cpu0 = time.process_time()
    sent = accepted = rejected = dropped = 0
    try:
        o = rows.op("trace_open_live", lambda: ecall(c, "trace_open", session=LIVE, create=True))
        if o is None:
            return 1
        cap = o["lease"]["cap"]
        i, nxt = 0, time.perf_counter()
        batch, interval = spec["batch"], spec["interval"]
        while not stop.exists():
            events = [trace_event(i + j, source="live") for j in range(batch)]
            r = rows.op("trace_append",
                        lambda: ecall(c, "trace_append", session=LIVE, cap=cap, events=events))
            sent += batch
            if r is not None:
                accepted += r.get("accepted", 0)
                rejected += len(r.get("rejected") or [])
                dropped += r.get("dropped_budget", 0)
            i += batch
            if (i // batch) % 20 == 0:
                rows.op("trace_mark", lambda: ecall(c, "trace_mark", session=LIVE, cap=cap, label="bench-%d" % i))
            nxt += interval
            time.sleep(max(0.0, nxt - time.perf_counter()))
        rows.op("trace_close_live", lambda: ecall(c, "trace_close", session=LIVE, cap=cap))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.raw({"op": "trace_writer_total", "ok": True, "sent": sent, "accepted": accepted, "rejected": rejected,
                  "dropped_budget": dropped, "cpu_ms": round((time.process_time() - cpu0) * 1000, 1)})
    return 0


def cmd_tracereader(spec_path):
    """An analysis agent reading traces while the capture goes on: reference reads (hashed) and live reads."""
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    rows = Rows(spec["rows"], spec["name"], "trace")
    c = rows.op("trace_connect", lambda: trace_connect(spec, spec["name"]))
    if c is None:
        return 1
    stop = Path(spec["stop"])
    ref = spec["ref"]
    cpu0 = time.process_time()
    n = 0
    check = [{"type": "forbidden", "kind": "core.error", "name": "bench-no-errors"}]
    try:
        while not stop.exists():
            n += 1
            rows.op("trace_info", lambda: ecall(c, "trace_info", session="ref-a"), tkey="trace|info|ref-a")
            rows.op("trace_query", lambda: ecall(c, "trace_query", session="ref-a", limit=100),
                    tkey="trace|query|ref-a")
            rows.op("trace_groups", lambda: ecall(c, "trace_query", session="ref-a", group_by="kind"),
                    tkey="trace|groups|ref-a")
            rows.op("trace_check", lambda: ecall(c, "trace_check", session="ref-a", assertions=check, persist=False),
                    tkey="trace|check|ref-a")
            if ref.get("ref-a", {}).get("write_event"):
                rows.op("trace_explain",
                        lambda: ecall(c, "trace_explain", session="ref-a", event_id=ref["ref-a"]["write_event"],
                                      max_events=50),
                        tkey="trace|explain|ref-a")
            if n % 4 == 1:
                rows.op("trace_diff", lambda: ecall(c, "trace_diff", a="ref-a", b="ref-b", group_by="kind"),
                        tkey="trace|diff|ref-a|ref-b")
            # the live session moves: these replies are timed, not hashed
            if spec.get("live_info", True):
                rows.op("live_info", lambda: ecall(c, "trace_info", session=LIVE))
            rows.op("live_query", lambda: ecall(c, "trace_query", session=LIVE, limit=100))
            rows.op("live_groups", lambda: ecall(c, "trace_query", session=LIVE, group_by="kind"))
            rows.op("live_check", lambda: ecall(c, "trace_check", session=LIVE, assertions=check, persist=False))
            time.sleep(spec.get("pause", 0.05))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.raw({"op": "trace_reader_total", "ok": True, "rounds": n,
                  "cpu_ms": round((time.process_time() - cpu0) * 1000, 1)})
    return 0


# ----------------------------------------------------------------------------------------------- agent child
def cmd_agent(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    gs = load_gs(spec["engine"])
    proj = spec["project"]
    rows = Rows(spec["rows"], spec["name"], proj.get("name") if isinstance(proj, dict) else proj)
    t_start = time.perf_counter()
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    c = rows.op("connect", lambda: d.connect(spec["name"], spec.get("harness", "multiproj-direct"),
                                              start=False, timeout=60))
    if c is None:
        rows.raw({"op": "agent_total", "ok": False, "wall_ms": round((time.perf_counter() - t_start) * 1000, 1)})
        return 1
    try:
        st = {}

        def open_view():
            o = ecall(c, "open_project", path=proj["gpr"], writable=False)
            p = ecall(c, "open_program", path=proj["program"], project=o["id"], writable=False)
            st.update(pid=o["id"], key=p["key"])
            return p
        if rows.op("open_view", open_view) is None:
            rows.raw({"op": "agent_total", "ok": False, "wall_ms": round((time.perf_counter() - t_start) * 1000, 1)})
            return 1
        key = st["key"]
        rng = random.Random(spec["seed"])

        def list_page(off, limit=500):
            return ecall(c, "functions", program=key, offset=off, limit=limit)

        work = []
        target_addrs = []
        if proj["kind"] == "cp":
            for off in spec["pages"]:
                r = rows.op("list_functions", lambda off=off: list_page(off),
                            key="%s|page|%d" % (proj["name"], off),
                            hashit=lambda r: [(f.get("address"), f.get("name"), f.get("size")) for f in r["functions"]])
                if r:
                    target_addrs += [f["address"] for f in r["functions"]
                                     if not f.get("external") and not f.get("thunk") and 0 < (f.get("size") or 0) <= 8000]
            own = strided(target_addrs, spec.get("decompiles", 38), offset=3)
            work += [("decompile_fresh", a) for a in own]
            work += [("decompile_shared", a) for a in spec["shared"]]
            work += [("read_script", spec["reads"][i:i + 1]) for i in range(min(spec.get("xrefs", 20), len(spec["reads"])))]
        elif proj["kind"] == "kotor":
            r = rows.op("list_functions", lambda: ecall(c, "functions", program=key, offset=spec.get("list_offset", 0),
                                                         limit=1000),
                        key="%s|page|%d" % (proj["name"], spec.get("list_offset", 0)),
                        hashit=lambda r: [(f.get("address"), f.get("name"), f.get("size")) for f in r["functions"]])
            work += [("decompile_hot", a) for a in spec["hot"]]
            work += [("decompile_fresh", a) for a in spec["fresh"]]
            work += [("read_script", spec["reads"][i:i + 4]) for i in range(0, len(spec["reads"]), 4)]
            work += [("info", None)]
        elif proj["kind"] == "k2":
            rows.op("list_functions", lambda: ecall(c, "functions", program=key, offset=0, limit=1000),
                    key="%s|page|0" % proj["name"],
                    hashit=lambda r: [(f.get("address"), f.get("name"), f.get("size")) for f in r["functions"]])
            work += [("decompile_fresh", a) for a in spec["fresh"]]
            work += [("read_script", spec["reads"][i:i + 2]) for i in range(0, len(spec["reads"]), 2)]
            work += [("xref_script", spec["xrefs"][i:i + 1]) for i in range(len(spec["xrefs"]))]
            work += [("info", None)]
        rng.shuffle(work)
        for op, arg in work:
            if op.startswith("decompile"):
                rows.op(op, lambda a=arg: ecall(c, "decompile", program=key, address=a, timeout=60, maxChars=10**7),
                        key="%s|view|%s" % (proj["name"], arg), hashit=decomp_hash)
            elif op in ("read_script", "xref_script"):
                rows.op(op, lambda a=arg: ecall(c, "script", script="BenchRead.java", args=list(a), program=key,
                                                 timeout=120),
                        key="%s|%s|%s" % (proj["name"], op, ",".join(arg)),
                        hashit=lambda r: (r or {}).get("output"))
            else:
                rows.op(op, lambda: ecall(c, "info", program=key),
                        key="%s|info" % proj["name"], hashit=lambda r: {k: r.get(k) for k in
                                                                        ("name", "analyzed", "functions", "sha256", "language", "imageBase")})
        subj = spec.get("edit")
        if subj:
            tag = "mp_%s" % spec["name"].replace("-", "_")
            ovl = "ov-%s" % spec["name"]
            if rows.op("overlay_open", lambda: ecall(c, "open_program", path=proj["program"], project=st["pid"],
                                                      overlay=ovl)):
                rows.op("overlay_edit", lambda: ecall(c, "apply_overlay", program=key, overlay=ovl, ops=[
                    {"op": "rename", "address": subj, "name": tag + "_ov"},
                    {"op": "comment", "address": subj, "text": "multiproj overlay " + tag, "type": "plate"}]))
                rows.op("decompile_overlay", lambda: ecall(c, "decompile", program=key, overlay=ovl, address=subj,
                                                           timeout=60, maxChars=10**7),
                        key="%s|overlay|%s|%s" % (proj["name"], subj, tag), hashit=decomp_hash)
                rows.op("overlay_drop", lambda: ecall(c, "drop_overlay", program=key, overlay=ovl))
        same = spec.get("overlay_same")
        if same:
            tag2 = "mp_same_%s" % spec["name"].replace("-", "_")
            ov2 = "ov2-%s" % spec["name"]
            if rows.op("overlay_same_open", lambda: ecall(c, "open_program", path=proj["program"], project=st["pid"],
                                                         overlay=ov2)):
                rows.op("overlay_same_edit", lambda: ecall(c, "apply_overlay", program=key, overlay=ov2, ops=[
                    {"op": "rename", "address": same, "name": tag2},
                    {"op": "comment", "address": same, "text": "multiproj same " + tag2, "type": "plate"}]))
                r2 = rows.op("overlay_same_decompile", lambda: ecall(c, "decompile", program=key, overlay=ov2,
                                                                    address=same, timeout=60, maxChars=10**7),
                             key="%s|overlay_same|%s|%s" % (proj["name"], same, tag2), hashit=decomp_hash)
                rows.raw({"op": "overlay_same_check", "ok": bool(r2) and r2.get("name") == tag2,
                          "seen": (r2 or {}).get("name"), "expected": tag2, "address": same})
                rows.op("overlay_same_drop", lambda: ecall(c, "drop_overlay", program=key, overlay=ov2))
        if spec.get("fork"):
            fdir = Path(spec["fork_dir"])
            fk = {}

            def fork():
                r = ecall(c, "fork_project", project=st["pid"], path=str(fdir), writable=True, timeout=600)
                fk["pid"] = r.get("project") or r.get("id")
                if isinstance(fk["pid"], dict):
                    fk["pid"] = fk["pid"].get("id")
                fk["gpr"] = r.get("path")
                p = ecall(c, "open_program", path=proj["program"], project=fk["pid"], writable=True, upgrade=True)
                fk["key"] = p["key"]
                return r
            if rows.op("fork", fork) is not None:
                tag = "mp_%s_fn" % spec["name"].replace("-", "_")
                ops = [{"op": "rename", "address": subj, "name": tag},
                       {"op": "comment", "address": subj, "text": "multiproj fork " + tag, "type": "plate"}]
                sig = spec.get("edit_sig") or ""
                sig = re.sub(r"__(?:thiscall|fastcall|stdcall|cdecl|vectorcall) ?", "", sig)
                if sig:
                    ops.append({"op": "signature", "address": subj, "signature": sig.replace(spec["edit_name"], tag)})
                rows.op("edit", lambda: ecall(c, "edit", program=fk["key"], ops=ops))
                rows.op("decompile_edited", lambda: ecall(c, "decompile", program=fk["key"], address=subj, timeout=60,
                                                           maxChars=10**7),
                        key="%s|fork|%s|%s" % (proj["name"], subj, tag), hashit=decomp_hash)
                rows.op("save", lambda: ecall(c, "save", program=fk["key"], comment="multiproj " + tag))
                rows.op("fork_close", lambda: ecall(c, "close_project", project=fk["pid"], discard=True))
                rows.raw({"op": "fork_info", "ok": True, "fork_gpr": fk.get("gpr"), "fork_pid": fk.get("pid"),
                          "program": proj["program"], "edit_address": subj, "new_name": tag,
                          "comment": "multiproj fork " + tag, "tag": tag})
        rows.op("close_view", lambda: ecall(c, "close_project", project=st["pid"]))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.raw({"op": "agent_total", "ok": True, "wall_ms": round((time.perf_counter() - t_start) * 1000, 1)})
    return 0


# ----------------------------------------------------------------------------------------------- Hydralysis child
def hy_boot(spec):
    sys.path.insert(0, str(HY_SRC))
    os.environ["HYDRALYSIS_ROOT"] = spec["hy_root"]
    os.environ["HYDRALYSIS_CONFIG"] = spec["hy_config"]
    os.environ.pop("HYDRALYSIS_AGENT_ID", None)
    return json.loads(Path(spec["hy_config"]).read_text(encoding="utf-8"))


class HyError(Exception):
    def __init__(self, code, message, payload=None):
        super().__init__(message)
        self.code, self.payload = code, payload or {}


def hy_asker(settings):
    from hydralysis import query
    runner = query.QueryRunner(settings)

    def ask(target, action, address="", limit=40, cursor="", **opts):
        try:
            return json.loads(runner.query(target, action, address, limit=limit, cursor=cursor, timeout_s=120,
                                           options=opts or None))
        except RuntimeError as e:
            text = str(e)
            payload = None
            for cand in (text, text.split(": ", 1)[-1]):
                with contextlib.suppress(ValueError):
                    payload = json.loads(cand)
                    break
            if isinstance(payload, dict):
                raise HyError(payload.get("error") or payload.get("code") or "error", text[:300], payload) from e
            raise HyError("error", text[:300]) from e
    return ask


def cmd_hyagent(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    settings = hy_boot(spec)
    ask = hy_asker(settings)
    rows = Rows(spec["rows"], spec["name"], "cp")
    t_start = time.perf_counter()
    me = spec["name"]
    target = "cp"
    try:
        r = rows.op("hy_functions", lambda: ask(target, "functions", cursor=spec["range_start"], limit=200),
                    key="cp|hy|functions|page0", hashit=lambda r: [(f.get("address"), f.get("name")) for f in r.get("functions", [])])
        rows.raw({"op": "hy_range", "ok": True, "returned": len((r or {}).get("functions") or []),
                  "first": ((r or {}).get("functions") or [{}])[0].get("address")})
        addrs = [f["address"] for f in (r or {}).get("functions") or [] if f.get("address")]
        own = strided(addrs, spec.get("decompiles", 38), offset=1)
        ownset = set(own)
        xrefs = [a for a in strided(addrs, 20, offset=3) if a not in ownset][:20]
        # The edit/publish runs before the queries, so the other six CP agents are still reading when the
        # generation is built; a function no reference reaches keeps the rename out of everybody's C text.
        subj = spec["edit"]
        leaf_scan = {"op": "hy_leaf_scan", "ok": False, "candidates": 0}
        t_leaf = time.time()
        for cand in addrs[:40]:
            leaf_scan["candidates"] += 1
            try:
                x = ask(target, "xrefs", cand, limit=50)
            except Exception:  # noqa: BLE001
                continue
            refs = x.get("references") or []
            if not any((ref.get("type") or "DATA") != "DATA" for ref in refs):
                subj = cand
                leaf_scan["ok"] = True
                break
        leaf_scan["subject"] = subj
        leaf_scan["s"] = round(time.time() - t_leaf, 2)
        rows.raw(leaf_scan)
        rev = lambda: ask(target, "status", **{"as": me}).get("view_revision", 0)  # noqa: E731
        tag = "mp_%s" % me.replace("-", "_")
        res = {}
        if rows.op("hy_edit", lambda: ask(target, "type_edit", subj, kind="rename", name=tag, source="multiproj",
                                          expect_revision=rev(), **{"as": me})) is not None:
            def publish():
                p = ask(target, "type_edit", kind="publish", expect_revision=rev(), confirm_one_way_upgrade=True,
                        **{"as": me})
                csid = p.get("csid")
                deadline = time.time() + spec.get("publish_wait_s", 600)
                while time.time() < deadline:
                    q = ask(target, "status", show="queue", csid=csid, **{"as": me})
                    cs = q.get("changeset") or {}
                    if cs.get("state") in ("done", "unknown"):
                        res.update(outcome=cs.get("outcome"), csid=csid)
                        if cs.get("outcome") not in ("applied", "rebased", "converged", "skipped"):
                            raise HyError("publish_" + str(cs.get("outcome")), json.dumps(cs)[:300])
                        return cs
                    time.sleep(0.25)
                raise HyError("publish_undecided", csid)
            rows.op("hy_publish", publish)
            rows.raw({"op": "hy_publish_outcome", "ok": bool(res), "outcome": res.get("outcome"), "csid": res.get("csid")})
        work = [("hy_decompile", a) for a in own] + [("hy_decompile_shared", a) for a in spec["shared"]] + \
               [("hy_xrefs", a) for a in xrefs]
        random.Random(spec["seed"]).shuffle(work)
        for op, a in work:
            if op == "hy_xrefs":
                rows.op(op, lambda a=a: ask(target, "xrefs", a, limit=50), key="cp|hyxrefs|%s" % a, hashit=lambda r: r)
            else:
                rows.op(op, lambda a=a: ask(target, "decompile", a), key="cp|hy|%s" % a, hashit=lambda r: r)
        # the published generation must show the rename when read back through the target
        try:
            fr = ask(target, "functions", cursor=subj, limit=4)
            rows_ = fr.get("functions") or []
            hit = [x for x in rows_ if (x.get("address") or "").lower() == subj.lower()]
            first = hit[0] if hit else (rows_[0] if rows_ else {})
            rows.raw({"op": "hy_publish_readback", "ok": first.get("name") == tag,
                      "seen": first.get("name"), "expected": tag, "address": subj,
                      "read": [x.get("address") for x in rows_[:3]]})
        except Exception as ex:  # noqa: BLE001
            rows.raw({"op": "hy_publish_readback", "ok": False, "error": str(ex)[:200]})
    finally:
        rows.raw({"op": "agent_total", "ok": True, "wall_ms": round((time.perf_counter() - t_start) * 1000, 1)})
    return 0


# ----------------------------------------------------------------------------------------------- import child
def cmd_importer(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    gs = load_gs(spec["engine"])
    rows = Rows(spec["rows"], spec["name"], "eaw")
    t0 = time.perf_counter()
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    c = rows.op("connect", lambda: d.connect(spec["name"], "multiproj-importer", start=False, timeout=60))
    if c is None:
        return 1
    try:
        if not Path(spec["gpr"]).is_file():
            rows.op("project_create", lambda: ecall(c, "script", script="RusticSetup.java",
                                                     args=[str(spec["project_dir"]), spec["project_name"]], timeout=120))
        o = rows.op("open_project", lambda: ecall(c, "open_project", path=spec["gpr"], writable=True))
        if o is None:
            return 1
        imp = rows.op("import_analysis", lambda: ecall(c, "import", file=spec["exe"], project=o["id"], analyze=True,
                                                       timeout=3600, wait=3600000))
        if imp:
            rows.raw({"op": "import_detail", "ok": True,
                      "importSeconds": imp.get("importSeconds"),
                      "analysis": strip(imp.get("analysis")),
                      "program": imp.get("key")})
            rows.op("info", lambda: ecall(c, "info", program=imp["key"]),
                    key="eaw|info", hashit=lambda r: {k: r.get(k) for k in
                                                     ("name", "analyzed", "functions", "sha256", "language", "imageBase")})
        rows.op("close_project", lambda: ecall(c, "close_project", project=o["id"]))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.raw({"op": "agent_total", "ok": True, "wall_ms": round((time.perf_counter() - t0) * 1000, 1)})
    return 0


# ----------------------------------------------------------------------------------------------- Hydralysis setup
def cmd_hysetup(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    settings = hy_boot(spec)
    from hydralysis import preparation
    out = {"targets": {}}
    for t in spec["targets"]:
        t0 = time.time()
        r = preparation.adopt(settings, t["gpr"], exe=t["exe"], target=t["name"])
        out["targets"][t["name"]] = {"s": round(time.time() - t0, 2),
                                    "result": {k: r.get(k) for k in ("state", "registered", "copied", "imported",
                                                                     "written", "functions", "reason")}}
        if not r.get("registered", True) and r.get("state") not in (None, "registered", "done", "adopted"):
            out["error"] = r
    out["warm"] = {}
    if spec.get("warm_target"):
        ask = hy_asker(settings)
        t0 = time.time()
        try:
            r = ask(spec["warm_target"], "functions", limit=5)
            out["warm"][spec["warm_target"]] = {"s": round(time.time() - t0, 2), "functions": len(r.get("functions") or [])}
        except Exception as ex:  # noqa: BLE001
            out["warm"][spec["warm_target"]] = {"error": str(ex)[:300]}
    write_json(spec["out"], out)
    return 0 if not out.get("error") else 1


# ----------------------------------------------------------------------------------------------- monitor
class Monitor(threading.Thread):
    def __init__(self, name, engine, state, out, stop_evt):
        super().__init__(daemon=True)
        self.name, self.engine, self.state, self.out = name, engine, state, out
        self.stop_evt = stop_evt
        self.pid = None
        self.errors = 0

    def run(self):
        try:
            gs = load_gs(self.engine)
            d = gs.Daemon(self.engine, str(self.state), INSTANCE)
            c = d.connect("monitor-" + self.name, "multiproj-monitor", start=False, timeout=30)
        except Exception as ex:  # noqa: BLE001
            with open(self.out, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": time.time(), "monitor_error": str(ex)[:300]}) + "\n")
            return
        try:
            while not self.stop_evt.is_set():
                rec = {"t": time.time(), "daemon": self.name}
                try:
                    h = c.call("health")
                    rec["state"] = h.get("state")
                    rec["lanes"] = h.get("lanes")
                    rec["mem"] = h.get("memory")
                    rec["deadlocked"] = len(h.get("deadlocked") or [])
                    rec["abandoned"] = len(h.get("abandoned") or [])
                except Exception as ex:  # noqa: BLE001
                    self.errors += 1
                    rec["health_error"] = str(ex)[:200]
                try:
                    s = c.call("status")
                    rec["waits"] = s.get("waits")
                    rec["decompileBackend"] = s.get("decompileBackend")
                    sch = s.get("scheduler") or {}
                    rec["scheduler"] = {k: sch.get(k) for k in ("maint", "waiting", "oldestWaitMs", "starving") if k in sch}
                    reqs = []
                    for r in (s.get("requests") or []):
                        reqs.append({k: r.get(k) for k in ("cmd", "client", "ms", "queue", "lane") if k in r})
                    rec["requests"] = reqs[:40]
                except Exception as ex:  # noqa: BLE001
                    self.errors += 1
                    rec["status_error"] = str(ex)[:200]
                with open(self.out, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
                self.stop_evt.wait(1.0)
        finally:
            with contextlib.suppress(Exception):
                c.close()


# ----------------------------------------------------------------------------------------------- run
def project_paths(run: Path, sources: dict):
    return {
        "cp": {"name": "cp", "kind": "cp", "gpr": str(run / "projects/cp/cp.gpr"),
               "program": "/Cyberpunk2077.exe"},
        "kotor": {"name": "kotor", "kind": "kotor", "gpr": str(run / "projects/kotor/kotor.gpr"),
                  "program": "/swkotor.exe"},
        "k2": {"name": "k2", "kind": "k2", "gpr": str(run / "projects/k2/corpus.gpr"),
               "program": "/swkotor2.exe"},
    }


def setup_state(root: Path, engine: str, agents: int, scripts: list[Path]):
    state = root / "hydra" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (root / "hydra" / "tmp").mkdir(parents=True, exist_ok=True)
    users = root / "hydra" / "user-scripts"
    users.mkdir(parents=True, exist_ok=True)
    for s in scripts:
        shutil.copy2(s, users / s.name)
    cfg = {"scriptPath": [str(root / "hydra" / "scripts"), str(users)],
           "tmpdir": str(root / "hydra" / "tmp"), "idleTimeout": 1800, "keepWarm": 1800,
           "java": JAVA, "maxLong": max(8, -(-agents * 3 // 2)), "maxQuick": max(16, agents * 2)}
    (state / "config.json").write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    return state


def cmd_run(a):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = Path(a.work) / ("%s-%s" % (a.label, stamp))
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for d in ("projects", "rows", "specs", "logs", "state", "forks"):
        (root / d).mkdir(parents=True)
    engine = str(Path(a.engine))
    os.environ.pop("HYDRA_CPU_PROFILE", None)
    if a.cpu_profile:
        os.environ["HYDRA_CPU_PROFILE"] = a.cpu_profile
    src = {"cp": Path(a.cp_project), "kotor": Path(a.kotor_project), "k2": Path(a.k2_project)}
    bins = Path(a.bin_dir)
    res = {"label": a.label, "engine": engine, "shape": a.shape, "started": stamp, "root": str(root),
           "agents": 16, "claim_cores": a.claim_cores, "cpus": os.cpu_count(), "phases": {},
           "cpu_profile": a.cpu_profile or "", "trace_readers": a.trace_readers}
    slots = Path("E:/Projects/Hydra/_logs/slots")
    held = {}
    if slots.is_dir():
        for p in sorted(slots.glob("cores-*.lock")):
            with contextlib.suppress(OSError, ValueError):
                pid, cores = p.read_text().split()
                held[p.name] = {"pid": int(pid), "cores": float(cores)}
    res["cores_held_at_start"] = held
    sampler = Sampler()
    sampler.start()
    load = LoadMon()
    load.start()
    T, E = {"start": time.perf_counter()}, {"start": time.time()}
    c0 = sampler.cpu()
    rows_dir = root / "rows"
    daemons = {}
    stop_evt = threading.Event()
    monitors, children, logs = [], [], []
    gs = load_gs(engine)

    def state_of(name):
        return daemons[name]["state"] if a.shape == "b" else daemons["all"]["state"]

    def conn(state, name="setup"):
        return gs.Daemon(engine, str(state), INSTANCE).connect(name, "multiproj", start=False, timeout=60)

    try:
        # ---- copies and read-only project hashes
        t_copy = time.perf_counter()
        for k, srcp in src.items():
            dst = root / "projects" / k
            dst.mkdir(parents=True)
            gpr = {"cp": "cp.gpr", "kotor": "kotor.gpr", "k2": "corpus.gpr"}[k]
            rep = gpr[:-4] + ".rep"
            shutil.copy2(srcp / gpr, dst / gpr)
            copytree_fast(srcp / rep, dst / rep)
        res["phases"]["copy"] = {"wall_s": round(time.perf_counter() - t_copy, 2)}
        projects = project_paths(root, src)
        scripts = [HERE / "scripts/BenchRead.java", HERE / "scripts/CheckEdit.java",
                   HERE / "scripts/RusticSetup.java", HERE / "scripts/SetAnalyzed.java"]
        client = str(Path(engine) / "Ghidra/Features/HeadlessSession/support/ghidra_session.py")
        cfg = {"hydra_dir": engine, "hydra_client": client, "hydra_idle_s": 1800, "java_home": JAVA,
               "expected_agents": 16}
        if os.environ.get("BENCH_ALLOW_UNPINNED", "1") != "0":   # source-built installs carry release "dev"
            cfg["hydra_allow_unpinned"] = True
        # The reused Cyberpunk project comes from a time-capped import+analysis (the auto-analysis hit its
        # 900 s bound), so its analysed flag is not set and Hydralysis refuses it. Mark it (a flag, no
        # function, symbol or byte changes) and save, on this run's copy only.
        t_prep = time.perf_counter()
        prep_state = setup_state(root / "state" / "prep", engine, 1, scripts)
        dprep = gs.Daemon(engine, str(prep_state), INSTANCE)
        cprep = dprep.connect("prep-cp", "multiproj", start=True, timeout=180)
        cpinfo = {}
        try:
            o = cprep.call("open_project", path=projects["cp"]["gpr"], writable=True)
            p = cprep.call("open_program", path=projects["cp"]["program"], project=o["id"], writable=True)
            r = cprep.call("script", script="SetAnalyzed.java", program=p["key"], timeout=120)
            cprep.call("save", program=p["key"], comment="multiproj setup: analysed flag")
            i = cprep.call("info", program=p["key"])
            cpinfo = {"analyzed_before": p.get("analyzed"), "analyzed": i.get("analyzed"),
                      "functions": i.get("functions"), "script": (r or {}).get("output", "").strip()}
            cprep.call("close_project", project=o["id"])
        except Exception as ex:  # noqa: BLE001
            cpinfo = {"error": str(ex)[:300]}
        finally:
            with contextlib.suppress(Exception):
                cprep.close()
            with contextlib.suppress(Exception):
                dprep.stop(force=True, timeout=120)
        res["phases"]["prep_cp"] = {"wall_s": round(time.perf_counter() - t_prep, 2), **cpinfo}
        res["project_hash_before"] = {k: tree_hash(root / "projects" / k) for k in projects}
        res["binaries"] = {}
        for exe in ("Cyberpunk2077.exe", "swkotor.exe", "swkotor2.exe", "sweaw.exe"):
            p = bins / exe
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            res["binaries"][exe] = {"bytes": p.stat().st_size, "sha256": h.hexdigest()}

        # ---- daemons
        t_daemon = time.perf_counter()
        hys = []
        if a.shape == "a":
            r = root / "state" / "all"
            setup_state(r, engine, 16, scripts)
            hys.append(("all", r, [("cp", projects["cp"]), ("kotor", projects["kotor"]), ("k2", projects["k2"])],
                        "cp"))
        else:
            for name in ("cp", "kotor", "k2"):
                r = root / "state" / name
                setup_state(r, engine, {"cp": 8, "kotor": 7, "k2": 4}[name], scripts)
                hys.append((name, r, [(name, projects[name])], "cp" if name == "cp" else None))
        for name, r, targets, warm in hys:
            expected = 16 if a.shape == "a" else {"cp": 8, "kotor": 7, "k2": 4}[name]
            conf = dict(cfg, root=str(r), expected_agents=expected)
            (r / "config.json").write_text(json.dumps(conf, indent=1), encoding="utf-8")
            spec = {"hy_root": str(r), "hy_config": str(r / "config.json"),
                    "out": str(root / ("hysetup-%s.json" % name)),
                    "targets": [{"name": t, "gpr": p["gpr"],
                                 "exe": str(bins / ("Cyberpunk2077.exe" if t == "cp" else
                                                    ("swkotor.exe" if t == "kotor" else "swkotor2.exe")))}
                                for t, p in targets],
                    "warm_target": warm}
            sp = root / "specs" / ("hysetup-%s.json" % name)
            write_json(sp, spec)
            p, lf = spawn_child(["hysetup", str(sp)], root / "logs" / ("hysetup-%s.log" % name))
            logs.append(lf)
            p.wait()
            f = root / ("hysetup-%s.json" % name)
            res.setdefault("hysetup", {})[name] = json.loads(f.read_text()) if f.is_file() else {"rc": p.returncode}
            st = r / "hydra" / "state"
            pid = state_pid(st)
            if pid:
                daemons[name if a.shape == "b" else "all"] = {"state": st, "pid": pid}
                sampler.add_root(pid)
        if a.shape == "b":
            r = root / "state" / "eaw"
            st = setup_state(r, engine, 2, scripts)
            d = gs.Daemon(engine, str(st), INSTANCE)
            c = d.connect("setup-eaw", "multiproj", start=True, timeout=180)
            c.close()
            pid = state_pid(st)
            daemons["eaw"] = {"state": st, "pid": pid}
            sampler.add_root(pid)
        res["phases"]["daemon"] = {"wall_s": round(time.perf_counter() - t_daemon, 2),
                                   "daemons": {k: v["pid"] for k, v in daemons.items()}}
        # ---- program counts, kotor/k2 lists, CP shared/hy pages, CP read pages, warm scripts, EaW project
        t_setup = time.perf_counter()
        info, funcs, cp_read_pages = {}, {}, {}
        for name in ("cp", "kotor", "k2"):
            pj = projects[name]
            c = conn(state_of(name), "setup-" + name)
            try:
                o = c.call("open_project", path=pj["gpr"], writable=False)
                p = c.call("open_program", path=pj["program"], project=o["id"], writable=False)
                info[name] = {k: p.get(k) for k in ("name", "key", "functions", "analyzed", "sha256", "language",
                                                    "imageBase", "revision")}
                if name in ("kotor", "k2"):
                    fl, off = [], 0
                    while True:
                        r = c.call("functions", program=p["key"], offset=off, limit=1000)
                        fl += r["functions"]
                        off += r.get("returned") or 0
                        if not r.get("truncated") or not off:
                            break
                    funcs[name] = [f for f in fl if not f.get("external") and not f.get("thunk")
                                   and 0 < (f.get("size") or 0) <= 20000]
                else:
                    r = c.call("functions", program=p["key"], offset=50000, limit=500)
                    funcs["cp_shared"] = [f for f in r["functions"] if not f.get("external")
                                          and not f.get("thunk") and 0 < (f.get("size") or 0) <= 8000]
                    total = int(info[name]["functions"])
                    r = c.call("functions", program=p["key"], offset=int(total * 6 / 7), limit=200)
                    funcs["cp_hy"] = [f for f in r["functions"] if not f.get("external") and not f.get("thunk")]
                    for i in range(6):
                        start = int(total * i / 7)
                        r = c.call("functions", program=p["key"], offset=start + 8000, limit=500)
                        cp_read_pages[i] = [f["address"] for f in r["functions"]
                                            if not f.get("external") and not f.get("thunk")]
                c.call("close_project", project=o["id"])
            finally:
                with contextlib.suppress(Exception):
                    c.close()
        res["programs"] = info
        res["funcs"] = {"kotor": len(funcs.get("kotor", [])), "k2": len(funcs.get("k2", [])),
                        "cp": info.get("cp", {}).get("functions"),
                        "cp_shared_page": len(funcs.get("cp_shared", [])), "cp_hy_range": len(funcs.get("cp_hy", []))}
        c = conn(state_of("kotor"), "warm-kotor")
        try:
            o = c.call("open_project", path=projects["kotor"]["gpr"], writable=False)
            p = c.call("open_program", path=projects["kotor"]["program"], project=o["id"], writable=False)
            c.call("script", script="BenchRead.java", args=[funcs["kotor"][0]["address"]], program=p["key"],
                   timeout=120)
            c.call("script", script="CheckEdit.java", args=[funcs["kotor"][1]["address"]], program=p["key"],
                   timeout=120)
            c.call("close_project", project=o["id"])
        finally:
            with contextlib.suppress(Exception):
                c.close()
        c = conn(state_of("eaw") if a.shape == "b" else state_of("cp"), "warm-eaw")
        try:
            c.call("script", script="RusticSetup.java", args=[str(root / "projects/eaw"), "eaw"], timeout=120)
        finally:
            with contextlib.suppress(Exception):
                c.close()
        trace_ref = {}
        if a.trace_readers > 0:
            trace_ref = seed_reference_sessions(engine, state_of("cp"))
            res["trace_ref"] = trace_ref
        res["phases"]["setup_reads"] = {"wall_s": round(time.perf_counter() - t_setup, 2)}
        # ---- specs
        specs = []
        shared_cp = [f["address"] for f in strided(funcs.get("cp_shared", []), 6, offset=2)[:2]]
        if len(shared_cp) < 2:
            shared_cp = [f["address"] for f in (funcs.get("cp_shared") or [])[:2]]
        kotor = funcs.get("kotor") or []
        k2 = funcs.get("k2") or []
        hot_k = strided(kotor, 10, offset=5)
        slices_k = [kotor[int(len(kotor) * i / 6):int(len(kotor) * (i + 1) / 6)] for i in range(6)]
        for i, sl in enumerate(slices_k):
            fresh = strided(sl, 15, offset=7)
            freshset = {f["address"] for f in fresh}
            picks = [x for x in strided(sl, 40, offset=11) if x["address"] not in freshset]
            edit = picks[0] if picks else fresh[0]
            spec = {"name": "kotor-%02d" % i, "engine": engine, "state": str(state_of("kotor")),
                    "rows": str(rows_dir / ("kotor-%02d.jsonl" % i)), "seed": 1000 + i,
                    "project": dict(projects["kotor"]), "list_offset": i * 300,
                    "hot": [f["address"] for f in hot_k], "fresh": [f["address"] for f in fresh],
                    "reads": [f["address"] for f in strided(sl, 8, offset=23)],
                    "edit": edit["address"], "edit_name": edit["name"],
                    "overlay_same": hot_k[0]["address"] if hot_k else None,
                    "fork": i in (0, 2, 4), "fork_dir": str(root / "forks" / ("kotor-%02d" % i))}
            specs.append(spec)
        c = conn(state_of("kotor"), "sigs")
        try:
            o = c.call("open_project", path=projects["kotor"]["gpr"], writable=False)
            p = c.call("open_program", path=projects["kotor"]["program"], project=o["id"], writable=False)
            for spec in specs:
                if spec["fork"]:
                    r = c.call("decompile", program=p["key"], address=spec["edit"], timeout=60, maxChars=10**7)
                    spec["edit_sig"] = (r.get("signature") or "").rstrip(";")
            c.call("close_project", project=o["id"])
        finally:
            with contextlib.suppress(Exception):
                c.close()
        slices_2 = [k2[int(len(k2) * i / 3):int(len(k2) * (i + 1) / 3)] for i in range(3)]
        for i, sl in enumerate(slices_2):
            spec = {"name": "k2-%02d" % i, "engine": engine, "state": str(state_of("k2")),
                    "rows": str(rows_dir / ("k2-%02d.jsonl" % i)), "seed": 2000 + i,
                    "project": dict(projects["k2"]),
                    "fresh": [f["address"] for f in strided(sl, 12, offset=3)],
                    "reads": [f["address"] for f in strided(sl, 4, offset=17)],
                    "xrefs": [f["address"] for f in strided(sl, 6, offset=9)]}
            specs.append(spec)
        total_cp = int(info.get("cp", {}).get("functions") or 0)
        for i in range(6):
            start = int(total_cp * i / 7)
            spec = {"name": "cp-%02d" % i, "engine": engine, "state": str(state_of("cp")),
                    "rows": str(rows_dir / ("cp-%02d.jsonl" % i)), "seed": 3000 + i,
                    "project": dict(projects["cp"]),
                    "pages": [start + 5000, start + 5500, start + 6000],
                    "decompiles": 38, "xrefs": 20, "shared": shared_cp,
                    "reads": strided(cp_read_pages.get(i, []), 20, offset=1)}
            if spec["reads"]:
                spec["edit"] = spec["reads"][0]
            specs.append(spec)
        hy_first = (funcs.get("cp_hy") or [{}])[0].get("address") or "0x140001000"
        hy_end = (funcs.get("cp_hy") or [{}])[-1].get("address") or hy_first
        hy_spec = {"name": "cp-hy", "hy_root": str(root / "state" / ("cp" if a.shape == "b" else "all")),
                   "hy_config": str(root / "state" / ("cp" if a.shape == "b" else "all") / "config.json"),
                   "rows": str(rows_dir / "cp-hy.jsonl"), "seed": 3999, "decompiles": 38,
                   "shared": shared_cp, "range_start": hy_first, "range_end": hy_end, "edit": hy_first,
                   "publish_wait_s": 600}
        specs.append(hy_spec)
        imp = {"name": "eaw-import", "engine": engine, "state": str(state_of("eaw") if a.shape == "b" else
                                                                    state_of("cp")),
               "rows": str(rows_dir / "eaw-import.jsonl"), "project_dir": str(root / "projects/eaw"),
               "project_name": "eaw", "gpr": str(root / "projects/eaw/eaw.gpr"),
               "exe": str(bins / "sweaw.exe")}
        res["shared_cp"] = shared_cp
        res["slices"] = {"cp_total": total_cp, "cp_hy_range": [hy_first, hy_end],
                         "kotor": len(kotor), "k2": len(k2)}
        for spec in specs:
            write_json(root / "specs" / (spec["name"] + ".json"), spec)
        write_json(root / "specs" / "eaw-import.json", imp)
        # ---- monitors
        for name, d in daemons.items():
            m = Monitor(name, engine, d["state"], root / "logs" / ("monitor-%s.jsonl" % name), stop_evt)
            m.start()
            monitors.append(m)
        # ---- workload
        T["work_start"], E["work_start"] = time.perf_counter(), time.time()
        c2 = sampler.cpu()
        for spec in specs:
            kind = "hyagent" if spec["name"] == "cp-hy" else "agent"
            py = HY_PYTHON if kind == "hyagent" else sys.executable
            p, lf = spawn_child([kind, str(root / "specs" / (spec["name"] + ".json"))],
                                root / "logs" / (spec["name"] + ".log"), python=py)
            children.append((spec["name"], p))
            logs.append(lf)
            sampler.add_root(p.pid)
        p, lf = spawn_child(["importer", str(root / "specs" / "eaw-import.json")],
                            root / "logs" / "eaw-import.log")
        children.append(("eaw-import", p))
        logs.append(lf)
        sampler.add_root(p.pid)
        stop_file = root / "stop-trace"
        trace_children = []
        if a.trace_readers > 0:
            tstate = str(state_of("cp"))
            write_json(root / "specs" / "trace-writer.json",
                       {"name": "trace-writer", "engine": engine, "state": tstate,
                        "rows": str(rows_dir / "trace-writer.jsonl"), "stop": str(stop_file),
                        "batch": a.trace_batch, "interval": a.trace_interval})
            p, lf = spawn_child(["tracewriter", str(root / "specs" / "trace-writer.json")],
                                root / "logs" / "trace-writer.log")
            trace_children.append(("trace-writer", p))
            logs.append(lf)
            sampler.add_root(p.pid)
            for k in range(a.trace_readers):
                nm = "trace-reader-%02d" % k
                write_json(root / "specs" / (nm + ".json"),
                           {"name": nm, "engine": engine, "state": tstate, "rows": str(rows_dir / (nm + ".jsonl")),
                            "stop": str(stop_file), "ref": trace_ref, "pause": a.trace_pause,
                            "live_info": not a.trace_no_live_info})
                p, lf = spawn_child(["tracereader", str(root / "specs" / (nm + ".json"))],
                                    root / "logs" / (nm + ".log"))
                trace_children.append((nm, p))
                logs.append(lf)
                sampler.add_root(p.pid)
        deadline = time.time() + a.max_s
        while True:
            alive = [n for n, p in children if p.poll() is None]
            if not alive:
                break
            if time.time() > deadline:
                for _, p in children:
                    with contextlib.suppress(Exception):
                        if p.poll() is None:
                            p.kill()
                res["timed_out"] = True
                break
            time.sleep(0.2)
        stop_file.write_text("stop", encoding="utf-8")
        for _, p in trace_children:
            try:
                p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
        T["work_end"], E["work_end"] = time.perf_counter(), time.time()
        c3 = sampler.cpu()
        res["exit_codes"] = {n: p.returncode for n, p in children}
        res["trace_exit_codes"] = {n: p.returncode for n, p in trace_children}
        res["verify"] = verify_forks(gs, engine, root, projects, daemons, a.shape)
        res["project_hash_after"] = {k: tree_hash(root / "projects" / k) for k in projects}
    finally:
        stop_evt.set()
        for m in monitors:
            m.join(3)
        for lf in logs:
            with contextlib.suppress(Exception):
                lf.close()
        for name, d in daemons.items():
            with contextlib.suppress(Exception):
                gs.Daemon(engine, str(d["state"]), INSTANCE).stop(force=True, timeout=120)
            pid = state_pid(d["state"]) or d.get("pid")
            if pid and _pid_alive(pid):
                with contextlib.suppress(Exception):
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=60)
        T["end"], E["end"] = time.perf_counter(), time.time()
        time.sleep(0.5)
        c4 = sampler.cpu()
        sampler.stop_evt.set()
        sampler.join(2)
        load.stop_evt.set()
        load.join(2)
        if "work_start" in T and "work_end" in T:
            res["phases"]["workload"] = {"wall_s": round(T["work_end"] - T["work_start"], 2),
                                         "cpu_s": cpu_delta(c2, c3),
                                         "memory": sampler.memory(T["work_start"], T["work_end"]),
                                         "load": load.window(E["work_start"], E["work_end"])}
        res["phases"]["total"] = {"wall_s": round(T["end"] - T["start"], 2),
                                  "cpu_s": cpu_delta(c0, c4),
                                  "memory": sampler.memory(T["start"], T["end"]),
                                  "load": load.window(E["start"], E["end"]),
                                  "processes": c4["processes"]}
    # ---- aggregate rows
    rows = read_rows(rows_dir)
    res["ops"] = agg_ops(rows)
    res["agents"], res["projects"] = agg_agents(rows, res.get("programs") or {})
    oprows = [r for r in rows if "ms" in r]
    res["ops_total"] = {"n": len(oprows), "ok": sum(1 for r in oprows if r.get("ok")),
                        "errors": sum(1 for r in oprows if r.get("ok") is False)}
    coreops = [r for r in oprows if not str(r["op"]).startswith(("trace_", "live_"))]
    res["ops_total_core"] = {"n": len(coreops), "ok": sum(1 for r in coreops if r.get("ok")),
                             "errors": sum(1 for r in coreops if r.get("ok") is False)}
    tops = [r for r in oprows if str(r["op"]).startswith(("trace_", "live_"))]
    res["trace_ops"] = {"n": len(tops), "ok": sum(1 for r in tops if r.get("ok")),
                        "errors": sum(1 for r in tops if r.get("ok") is False),
                        "waited_replies": sum(1 for r in tops if r.get("waited")),
                        "queued_replies": sum(1 for r in tops if r.get("queue")),
                        "waited_replies_core": sum(1 for r in coreops if r.get("waited")),
                        "queued_replies_core": sum(1 for r in coreops if r.get("queue"))}
    thashes, tinconsistent = {}, {}
    for r in rows:
        if "tkey" in r:
            prev = thashes.setdefault(r["tkey"], r["tsha"])
            if prev != r["tsha"]:
                tinconsistent.setdefault(r["tkey"], sorted({prev, r["tsha"]}))
    if thashes:
        res["trace_correctness"] = {
            "keys": len(thashes), "inconsistent_in_run": tinconsistent or None,
            "errors": sorted(k for k, v in thashes.items() if str(v).startswith("ERR")),
            "digest": hashlib.sha256("\n".join("%s %s" % kv for kv in sorted(thashes.items())).encode()).hexdigest()}
    res["trace_agents"] = {r["agent"]: {k: r[k] for k in r if k not in ("agent", "op", "t", "ms", "ok", "project")}
                           for r in rows if r.get("op") in ("trace_writer_total", "trace_reader_total")}
    hashes, inconsistent = {}, {}
    for r in rows:
        if "key" in r and "sha" in r:
            prev = hashes.setdefault(r["key"], r["sha"])
            if prev != r["sha"]:
                inconsistent.setdefault(r["key"], sorted({prev, r["sha"]}))
    res["correctness"] = {"keys": len(hashes), "inconsistent_in_run": inconsistent or None,
                          "digest": hashlib.sha256("\n".join("%s %s" % kv for kv in sorted(hashes.items())).encode()).hexdigest()}
    res["monitor"] = summarize_monitors(root, daemons)
    hpath = out_dir / ("%s-%s.hashes.json" % (a.label, stamp))
    write_json(hpath, hashes)
    res["hashes_file"] = str(hpath)
    write_json(out_dir / ("%s-%s.json" % (a.label, stamp)), res)
    w = res["phases"].get("workload", {})
    print("workload wall %s s cpu %s mem peak %s mean %s ops %s/%s errors %s keys %s -> %s" % (
        w.get("wall_s"), (w.get("cpu_s") or {}).get("total"), (w.get("memory") or {}).get("peak_mb"),
        (w.get("memory") or {}).get("mean_mb"), res["ops_total"]["ok"], res["ops_total"]["n"],
        res["ops_total"]["errors"], len(hashes), out_dir / ("%s-%s.json" % (a.label, stamp))), flush=True)
    return 0


def copytree_fast(src: Path, dst: Path):
    dst.mkdir(parents=True, exist_ok=True)
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if p.is_dir():
            (dst / rel).mkdir(parents=True, exist_ok=True)
        else:
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst / rel)


def verify_forks(gs, engine, root, projects, daemons, shape):
    infos = []
    for f in sorted((root / "rows").glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            with contextlib.suppress(ValueError):
                r = json.loads(line)
                if r.get("op") == "fork_info":
                    infos.append(r)
    out = {"forks": len(infos), "ok": 0, "failed": []}
    if not infos:
        return out
    st = daemons["kotor"]["state"] if shape == "b" else daemons["all"]["state"]
    try:
        d = gs.Daemon(engine, str(st), INSTANCE)
        c = d.connect("verify", "multiproj-verify", start=False, timeout=60)
    except Exception as ex:  # noqa: BLE001
        out["error"] = str(ex)[:300]
        return out
    try:
        for info in infos:
            gpr = info.get("fork_gpr")
            try:
                o = c.call("open_project", path=gpr, writable=False)
                p = c.call("open_program", path=info["program"], project=o["id"], writable=False)
                r = c.call("script", script="CheckEdit.java", args=[info["edit_address"]], program=p["key"],
                           timeout=120)
                txt = (r or {}).get("output") or ""
                ok = (info["new_name"] in txt and info["comment"] in txt)
                dr = c.call("decompile", program=p["key"], address=info["edit_address"], timeout=60, maxChars=10**7)
                out.setdefault("decompiles", {})[info["new_name"]] = digest(decomp_hash(dr))
                c.call("close_project", project=o["id"])
                if ok:
                    out["ok"] += 1
                else:
                    out["failed"].append({"fork": gpr, "output": txt[:300]})
            except Exception as ex:  # noqa: BLE001
                out["failed"].append({"fork": gpr, "error": str(ex)[:300]})
    finally:
        with contextlib.suppress(Exception):
            c.close()
    return out


def read_rows(rows_dir):
    rows = []
    for f in sorted(Path(rows_dir).glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            with contextlib.suppress(ValueError):
                rows.append(json.loads(line))
    return rows


def agg_ops(rows):
    rows = [r for r in rows if "ms" in r]
    ops = {}
    for r in rows:
        ops.setdefault(r["op"], []).append(r)
    out = {}
    for op, rs in sorted(ops.items()):
        ms = [r["ms"] for r in rs if r.get("ok")]
        errs = {}
        for r in rs:
            if not r.get("ok"):
                errs[str(r.get("code"))] = errs.get(str(r.get("code")), 0) + 1
        waited = [r.get("waited") or {} for r in rs]
        out[op] = {"n": len(rs), "ok": len(ms), "p50_ms": pct(ms, .5), "p99_ms": pct(ms, .99),
                   "max_ms": max(ms) if ms else None, "errors": errs or None,
                   "waited_lock_ms": round(sum(w.get("lockMs", 0) for w in waited), 1),
                   "waited_slot_ms": round(sum(w.get("slotMs", 0) for w in waited), 1),
                   "waited_queue_ms": round(sum(w.get("queueMs", 0) for w in waited), 1),
                   "slot_queued": sum(1 for r in rs if r.get("queue")),
                   "srv_p50_ms": pct([r["srv_ms"] for r in rs if r.get("srv_ms") is not None], .5)}
    return out


def agg_agents(rows, programs):
    agents, projects = {}, {}
    for r in rows:
        if "ms" not in r and r["op"] != "agent_total":
            continue
        ag = r["agent"]
        a = agents.setdefault(ag, {"project": r.get("project"), "ops": 0, "ok": 0, "errors": 0,
                                   "decompiles": 0, "reads": 0, "edits": 0, "wall_ms": None,
                                   "first": r.get("t"), "last": r.get("t")})
        a["ops"] += 1
        if r.get("ok") is True:
            a["ok"] += 1
        elif r.get("ok") is False:
            a["errors"] += 1
        if r["op"] == "agent_total":
            a["wall_ms"] = r.get("ms")
        if r["op"].startswith("decompile"):
            a["decompiles"] += 1 if r.get("ok") else 0
        if r["op"].endswith("script"):
            a["reads"] += 1 if r.get("ok") else 0
        if r["op"] in ("edit", "apply_overlay", "hy_edit", "hy_publish"):
            a["edits"] += 1 if r.get("ok") else 0
        a["first"] = min(a["first"], r.get("t") or a["first"])
        a["last"] = max(a["last"], r.get("t") or a["last"])
        p = projects.setdefault(r.get("project"), {"agents": set(), "ops": 0, "ok": 0, "errors": 0,
                                                   "decompiles": 0, "start": r.get("t"), "end": r.get("t")})
        p["agents"].add(ag)
        p["ops"] += 1
        if r.get("ok") is True:
            p["ok"] += 1
        elif r.get("ok") is False:
            p["errors"] += 1
        if r["op"].startswith("decompile"):
            p["decompiles"] += 1 if r.get("ok") else 0
        p["start"] = min(p["start"], r.get("t") or p["start"])
        p["end"] = max(p["end"], r.get("t") or p["end"])
    for a in agents.values():
        if a["wall_ms"] is None and a["last"] and a["first"]:
            a["wall_ms"] = round((a["last"] - a["first"]) * 1000, 1)
        a["first"] = round(a["first"], 3) if a["first"] else None
        a["last"] = round(a["last"], 3) if a["last"] else None
    for p in projects.values():
        p["agents"] = sorted(p["agents"])
        p["wall_s"] = round((p["end"] - p["start"]), 2) if p["start"] and p["end"] else None
        p["start"], p["end"] = round(p["start"], 3) if p["start"] else None, round(p["end"], 3) if p["end"] else None
    return agents, projects


def summarize_monitors(root, daemons):
    out = {}
    for name in daemons:
        f = root / "logs" / ("monitor-%s.jsonl" % name)
        recs = []
        if f.is_file():
            for line in f.read_text(encoding="utf-8").splitlines():
                with contextlib.suppress(ValueError):
                    recs.append(json.loads(line))
        if not recs:
            out[name] = {"samples": 0}
            continue
        states = {}
        for r in recs:
            states[r.get("state")] = states.get(r.get("state"), 0) + 1
        lanes = {}
        maxq = {}
        starve = 0
        for r in recs:
            for lane, v in (r.get("lanes") or {}).items():
                lanes.setdefault(lane, []).append(v.get("inUse", 0))
                maxq[lane] = max(maxq.get(lane, 0), v.get("queued", 0))
                if v.get("starving"):
                    starve += 1
        waits = [r.get("waits") for r in recs if isinstance(r.get("waits"), dict)]
        first = waits[0] if waits else {}
        last = waits[-1] if waits else {}
        delta = {}
        for k in ("foreignBlocked", "singleFlightOpen", "contended"):
            a0 = (first.get(k) or {}).get("total", 0) if isinstance(first.get(k), dict) else (first.get(k) or 0)
            a1 = (last.get(k) or {}).get("total", 0) if isinstance(last.get(k), dict) else (last.get(k) or 0)
            delta[k] = a1 - a0
        out[name] = {"samples": len(recs), "states": states,
                     "max_queued": maxq, "starving_samples": starve,
                     "max_in_use": {k: max(v) for k, v in lanes.items()},
                     "last_waits": last, "first_waits": first, "waits_delta": delta,
                     "health_errors": sum(1 for r in recs if r.get("health_error")),
                     "status_errors": sum(1 for r in recs if r.get("status_error")),
                     "max_requests": max((len(r.get("requests") or []) for r in recs), default=0)}
    return out


# ----------------------------------------------------------------------------------------------- report helpers
def cmd_compare(paths):
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    hs = [json.loads(Path(r["hashes_file"]).read_text(encoding="utf-8")) for r in runs]
    base = hs[0]
    out = []
    for r, h in zip(runs[1:], hs[1:]):
        common = set(base) & set(h)
        diff = sorted(k for k in common if base[k] != h[k])
        out.append({"run": r["label"] + " " + r["started"] + " " + r["shape"], "common": len(common),
                    "differ": len(diff), "only_base": len(set(base) - set(h)), "only_this": len(set(h) - set(base)),
                    "first_differ": diff[:20]})
    print(json.dumps({"base": runs[0]["label"] + " " + runs[0]["started"], "vs": out}, indent=1))
    return 0


def cmd_table(paths):
    print("| run | shape | wall s | CPU s (java/decompile/python) | peak MB | mean MB | ops ok/all | errors | waits foreign | lock p99 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for p in paths:
        r = json.loads(Path(p).read_text(encoding="utf-8"))
        w = r["phases"].get("workload", {})
        c = w.get("cpu_s") or {}
        m = w.get("memory") or {}
        mon = list((r.get("monitor") or {}).values())
        fb = sum((x.get("last_waits") or {}).get("foreignBlocked", {}).get("total", 0) for x in mon)
        lp = [x.get("last_waits", {}).get("lockWaitP99Ms") for x in mon]
        print("| %s | %s | %s | %s (%s/%s/%s) | %s | %s | %s/%s | %s | %s | %s |" % (
            r["label"], r["shape"], w.get("wall_s"), c.get("total"), c.get("java"), c.get("decompile"),
            c.get("python"), m.get("peak_mb"), m.get("mean_mb"), r["ops_total"]["ok"], r["ops_total"]["n"],
            r["ops_total"]["errors"], fb, lp))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--engine", required=True)
    r.add_argument("--label", required=True)
    r.add_argument("--shape", choices=("a", "b"), required=True)
    r.add_argument("--work", default=str(WORK / "runs"))
    r.add_argument("--out", default=str(WORK / "results"))
    r.add_argument("--cp-project", default="C:/dev-overflow/hydra-perf/games-cp/proj/int5-an")
    r.add_argument("--kotor-project", default="D:/Projects/Hydra/_golden/kotor-src-copy")
    r.add_argument("--k2-project", default="C:/dev-overflow/hydra-perf/games-e/projects/latest/swkotor2")
    r.add_argument("--bin-dir", default=str(WORK / "bin"))
    r.add_argument("--max-s", type=int, default=1200)
    r.add_argument("--claim-cores", type=int, default=16)
    r.add_argument("--cpu-profile", default="", help="HYDRA_CPU_PROFILE for the daemons (generic, auto)")
    r.add_argument("--trace-readers", type=int, default=0, help="trace reader agents (>0 also starts the live capture)")
    r.add_argument("--trace-batch", type=int, default=200)
    r.add_argument("--trace-interval", type=float, default=0.1)
    r.add_argument("--trace-pause", type=float, default=0.05)
    r.add_argument("--trace-no-live-info", action="store_true",
                   help="readers skip trace_info on the live session (its cost grows with the session: a full-index digest)")
    for name in ("agent", "hyagent", "importer", "hysetup", "tracewriter", "tracereader"):
        p = sub.add_parser(name)
        p.add_argument("spec")
    c = sub.add_parser("compare")
    c.add_argument("runs", nargs="+")
    t = sub.add_parser("table")
    t.add_argument("runs", nargs="+")
    a = ap.parse_args(argv)
    if a.cmd == "tracewriter":
        return cmd_tracewriter(a.spec)
    if a.cmd == "tracereader":
        return cmd_tracereader(a.spec)
    if a.cmd == "agent":
        return cmd_agent(a.spec)
    if a.cmd == "hyagent":
        return cmd_hyagent(a.spec)
    if a.cmd == "importer":
        return cmd_importer(a.spec)
    if a.cmd == "hysetup":
        return cmd_hysetup(a.spec)
    if a.cmd == "compare":
        return cmd_compare(a.runs)
    if a.cmd == "table":
        return cmd_table(a.runs)
    return cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
