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
# limitations under the License.
"""Shared multi-agent benchmark: N simulated agents on one Hydra Engine daemon, several projects, several harnesses.

    python -I multiagent_bench.py run --engine <install> --label <name> [--agents 16] [--vmargs "-D... -D..."]
    python -I multiagent_bench.py compare <run.json> <run.json> [...]   # decompile/read reply hashes across runs
    python -I multiagent_bench.py table <run.json> [...]                # markdown table of runs
    python -I multiagent_bench.py summary <run.json> [...]              # medians per label, per-op table, correctness

What one `run` does (all under C:/dev-overflow/hydra-perf/bench/<label>-<time>, copies only):
  setup     copies _golden/kotor-src-copy and the fixture project _golden/projects/fixtures/fx-x64-diff1, then a
            Hydralysis process (the RusticRE venv Python, Hydralysis from the hy-integration worktree) adopts both
            projects as targets "kotor" and "fx"; that starts the one shared engine daemon (Hydralysis' own state dir and
            config, GHIDRA_SESSION_VMARGS applied). The bench then picks the decompile sets and the Hydralysis rename
            subjects (fx functions no CALL/JUMP reaches). Measured separately, not part of the workload figures.
  workload  N agent processes start together (default 16):
              direct agents (ghidra_session.py client, system Python; 3/4 of N): open view, list functions, decompiles
              (a shared hot set every agent repeats and a fresh slice of its own), reads (`info` and a GhidraScript that
              reads bytes, references and symbols), an overlay edit (rename + comment) and its decompile; every second
              direct agent also forks its project, edits the fork (rename, plate comment, signature), decompiles,
              saves it and drops the fork. Projects: two thirds kotor, one third fx.
              Hydralysis agents (QueryRunner in its own process, 1/4 of N, at least 2): functions, decompiles and xrefs
              on kotor, then on fx an edit in the agent's own view (type_edit rename) and a publish (seal, wait for the
              decision).
              2 subagent bursts (default 4 processes each, at 20 s and 50 s): connect, open the kotor view, a few
              decompiles and one read, exit.
  teardown  the daemon is stopped.
Measured: wall of each phase; per op type count, ops/s (over the workload wall), p50/p99/max latency, errors; CPU seconds
of the process tree (java, decompile.exe, agent Pythons; the bench process itself apart) from GetProcessTimes on handles
kept open from the first sighting (so exited processes count in full); committed memory (private bytes) of the tree,
sampled every 250 ms: peak and mean. Correctness: every decompile and read reply is hashed (volatile fields removed) per
(project, context, address); `compare` checks the hashes across runs and engines; a key with two different hashes in one
run is reported too.
Windows only (ctypes kernel32/psapi; psutil is not needed).

Semantic trace additions (12.3-hydra.6, WS-I "daemon impact"):
  --trace-readers N   N > 0 turns the trace load on: before the workload two closed reference sessions (ref-a, ref-b;
                      deterministic events) are written through the protocol; during it ONE live capture (a
                      `tracewriter` process appending --trace-batch events every --trace-interval s to the session
                      `live`, keyed strings included) and N `tracereader` processes (info, query page, group, check,
                      explain, a diff of ref-a against ref-b, and the same reads on the live session) run beside the
                      16 agents. The 412-key reply digest covers the agents' decompile/read replies only and must not
                      move; the trace replies of the CLOSED reference sessions have their own digest
                      (`trace_correctness`), which must be one value across runs, profiles and clients.
  --cpu-profile P     HYDRA_CPU_PROFILE for the daemon (`generic` or `auto`).
  Also recorded per run: daemon `status.waits` (foreignBlocked.total must be 0), system busy cores over the workload
  window, the CPU of the trace agents themselves (the python column includes them).
  --affinity N        resource-constrained run: this process, and therefore every child (the Hydralysis-started daemon, its
                      decompilers, the agents), is limited to logical CPUs 0..N-1 (SetProcessAffinityMask), so the daemon
                      sizes its pools from N granted CPUs. Logical CPUs 0-15 are the eight P-cores with SMT.
  BENCH_WORK / BENCH_HY_SRC override the work root and the Hydralysis source tree.
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
SAVE_REPLIES = bool(os.environ.get("BENCH_SAVE_REPLIES"))
HERE = Path(__file__).resolve().parent
GOLDEN = Path("D:/Projects/Hydra/_golden")
KOTOR_PROJECT = GOLDEN / "kotor-src-copy"
FX_PROJECT = GOLDEN / "projects/fixtures/fx-x64-diff1"
KOTOR_EXE = Path("C:/dev-overflow/hydra-perf/input/swkotor.exe")
FX_EXE = GOLDEN / "fixtures-build/x64/diff1.exe"
WORK = Path(os.environ.get("BENCH_WORK", "C:/dev-overflow/hydra-perf/trace-lnfr/work"))
HY_SRC = Path(os.environ.get("BENCH_HY_SRC", "E:/Projects/Hydra/wt/hy-final/src"))
HY_PYTHON = Path("D:/Projects/Hydra/RusticRE/.venv/Scripts/python.exe")
JAVA = "C:/dev-overflow/jdk/jdk-25.0.5+8"
INSTANCE = "rusticre"          # Hydralysis' daemon instance (hydra.INSTANCE)
VOLATILE = {"ms", "elapsedMs", "openMs", "waitedMs", "cached", "cache", "queue", "timing", "timings", "took_ms", "elapsed",
            "seq", "journalSeq", "revision", "projectRevision", "view_revision", "latest_editor", "generation",
            "working_copy", "overlay_id", "boot", "requestId", "id", "query_s", "script_s", "agent"}


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
    """(pid, parent pid, exe name) of every process."""
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

    def working_set(self) -> int:
        """Resident bytes (WorkingSetSize): the number a collector that maps its heap more than once (ZGC) is judged by,
        since its private bytes undercount."""
        m = PMCEX()
        m.cb = ctypes.sizeof(m)
        return m.WorkingSetSize if K32.K32GetProcessMemoryInfo(self.h, ctypes.byref(m), m.cb) else 0


def category(p: Proc, own: int) -> str:
    if p.pid == own:
        return "bench"
    if p.name == "java.exe" or p.name == "javaw.exe":
        return "java"
    if p.name == "decompile.exe":
        return "decompile"
    if p.name.startswith("python"):
        return "python"
    return "other"


class Sampler(threading.Thread):
    """Tracks this process, its descendants and the daemon (and its descendants); samples private bytes every 250 ms."""

    def __init__(self, interval=0.25):
        super().__init__(daemon=True)
        self.own = os.getpid()
        self.interval = interval
        self.procs: dict[int, Proc] = {}
        self.roots = {self.own}
        self.samples: list[tuple[float, int, dict, list]] = []   # (time, total private w/o bench, by category, top procs)
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
                    if p.created < parent.created:       # the parent pid was reused: not our child
                        K32.CloseHandle(p.h)
                        continue
                    self.procs[pid] = p
                    changed = True

    def sample(self):
        self.scan()
        by = {}
        detail = []
        ws = 0
        with self.lock:
            for p in self.procs.values():
                if p.alive():
                    c = category(p, self.own)
                    mb = p.private()
                    by[c] = by.get(c, 0) + mb
                    if c != "bench":
                        ws += p.working_set()
                    detail.append((p.name, p.pid, round(mb / 2**20, 1)))
        total = sum(v for k, v in by.items() if k != "bench")
        detail.sort(key=lambda d: -d[2])
        self.samples.append((time.perf_counter(), total, by, detail[:4], ws))

    def run(self):
        while not self.stop_evt.is_set():
            t0 = time.perf_counter()
            with contextlib.suppress(Exception):
                self.sample()
            self.stop_evt.wait(max(0.01, self.interval - (time.perf_counter() - t0)))

    def cpu(self) -> dict:
        self.scan()
        by = {}
        with self.lock:
            for p in self.procs.values():
                c = category(p, self.own)
                by[c] = by.get(c, 0.0) + p.cpu()
            counts = {}
            for p in self.procs.values():
                c = category(p, self.own)
                counts[c] = counts.get(c, 0) + 1
        return {"by": by, "processes": counts}

    def memory(self, t0, t1) -> dict:
        win = [s for s in self.samples if t0 <= s[0] <= t1]
        if not win:
            return {"samples": 0}
        peak = max(win, key=lambda s: s[1])
        return {"samples": len(win), "peak_mb": round(peak[1] / 2**20, 1), "mean_mb": round(statistics.mean(s[1] for s in win) / 2**20, 1),
                "peak_by_mb": {k: round(v / 2**20, 1) for k, v in peak[2].items()},
                "peak_java_mb": round(max(s[2].get("java", 0) for s in win) / 2**20, 1),
                "peak_detail": peak[3] if len(peak) > 3 else [],
                "peak_ws_mb": round(max(s[4] for s in win) / 2**20, 1), "mean_ws_mb": round(statistics.mean(s[4] for s in win) / 2**20, 1)}


def cpu_delta(a: dict, b: dict) -> dict:
    keys = set(a["by"]) | set(b["by"])
    d = {k: round(b["by"].get(k, 0.0) - a["by"].get(k, 0.0), 2) for k in sorted(keys)}
    d["total"] = round(sum(v for k, v in d.items() if k != "bench"), 2)
    return d


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


class Rows:
    """Result rows of one agent process: one JSON line per op."""

    def __init__(self, path, agent):
        self.f = open(path, "a", encoding="utf-8", buffering=1)
        self.agent = agent

    def op(self, name, fn, key=None, hashit=None, tkey=None):
        t0 = time.perf_counter()
        rec = {"agent": self.agent, "op": name, "t": time.time()}
        try:
            r = fn()
            rec["ok"] = True
            if key is not None:
                rec["key"] = key
                obj = hashit(r) if hashit else r
                rec["sha"] = digest(obj)
                if SAVE_REPLIES:
                    rec["reply"] = strip(obj)
            if tkey is not None:        # a trace reply of a closed reference session: its own digest
                rec["tkey"] = tkey
                rec["tsha"] = digest(hashit(r) if hashit else r)
            return r
        except Exception as ex:   # noqa: BLE001 - every failure is a counted result
            rec["ok"] = False
            rec["code"] = getattr(ex, "code", None) or type(ex).__name__
            rec["msg"] = str(ex)[:200]
            if key is not None:
                rec["key"] = key
                rec["sha"] = "ERR:" + str(rec["code"])
            if tkey is not None:
                rec["tkey"] = tkey
                rec["tsha"] = "ERR:" + str(rec["code"])
            return None
        finally:
            rec["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            self.f.write(json.dumps(rec) + "\n")


def load_gs(install):
    os.environ["GHIDRA_SESSION_JAVA_HOME"] = JAVA
    sys.path.insert(0, str(Path(install) / "Ghidra/Features/HeadlessSession/support"))
    import ghidra_session as gs  # noqa: E402
    return gs


def decomp_hash(r):
    return {k: r.get(k) for k in ("name", "entry", "completed", "signature", "c", "truncated", "error")} if isinstance(r, dict) else r


# ----------------------------------------------------------------------------------------------- direct agent
def cmd_agent(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    gs = load_gs(spec["engine"])
    rows = Rows(spec["rows"], spec["name"])
    rng = random.Random(spec["seed"])
    proj = spec["project"]
    pname = proj["name"]
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    c = rows.op("connect", lambda: d.connect(spec["name"], spec.get("harness", "bench-direct"), start=False))
    if c is None:
        return 1
    try:
        state = {}

        def open_view():
            o = c.call("open_project", path=proj["gpr"], writable=False)
            p = c.call("open_program", path=proj["program"], project=o["id"], writable=False)
            state.update(pid=o["id"], key=p["key"])
            return p
        if rows.op("open_view", open_view) is None:
            return 1
        key = state["key"]

        def list_functions():
            out, off = [], 0
            while True:
                r = c.call("functions", program=key, offset=off, limit=1000)
                out += r["functions"]
                if not r.get("truncated"):
                    return out
                off += r["returned"]
        fl = rows.op("list_functions", list_functions)
        work = [("decompile_hot", a) for a in spec["hot"]] + [("decompile_fresh", a) for a in spec["fresh"]]
        work += [("read_script", spec["reads"][i:i + 4]) for i in range(0, len(spec["reads"]), 4)]
        work += [("info", None)] * 2
        rng.shuffle(work)
        for op, arg in work:
            if op.startswith("decompile"):
                rows.op(op, lambda a=arg: c.call("decompile", program=key, address=a, timeout=120, maxChars=10**7),
                        key="%s|view|%s" % (pname, arg), hashit=decomp_hash)
            elif op == "read_script":
                rows.op(op, lambda a=arg: c.call("script", script="BenchRead.java", args=a, program=key, timeout=120),
                        key="%s|read|%s" % (pname, ",".join(arg)), hashit=lambda r: (r or {}).get("output"))
            else:
                rows.op(op, lambda: c.call("info", program=key))
        # overlay edit on the shared view (no write to the project)
        subj = spec["edit"]
        tag = "bench_%s" % spec["name"].replace("-", "_")
        ovl = "ov-%s" % spec["name"]
        if rows.op("overlay_open", lambda: c.call("open_program", path=proj["program"], project=state["pid"], overlay=ovl)):
            rows.op("overlay_edit", lambda: c.call("apply_overlay", program=key, overlay=ovl, ops=[
                {"op": "rename", "address": subj, "name": tag + "_ov"},
                {"op": "comment", "address": subj, "text": "bench overlay " + tag, "type": "plate"}]))
            rows.op("decompile_overlay", lambda: c.call("decompile", program=key, overlay=ovl, address=subj, timeout=120,
                                                        maxChars=10**7),
                    key="%s|overlay|%s|%s" % (pname, subj, tag), hashit=decomp_hash)
            rows.op("overlay_drop", lambda: c.call("drop_overlay", program=key, overlay=ovl))
        if spec.get("fork"):
            fdir = Path(spec["fork_dir"])
            fk = {}

            def fork():
                r = c.call("fork_project", project=state["pid"], path=str(fdir), writable=True, timeout=600)
                pj = r.get("project")
                fk["pid"] = r.get("id") or (pj.get("id") if isinstance(pj, dict) else pj)
                p = c.call("open_program", path=proj["program"], project=fk["pid"], writable=True, upgrade=True)
                fk["key"] = p["key"]
                return r
            if rows.op("fork", fork) is not None:
                sig = spec.get("edit_sig")
                ops = [{"op": "rename", "address": subj, "name": tag},
                       {"op": "comment", "address": subj, "text": "bench fork " + tag, "type": "plate"}]
                sig = re.sub(r"__(?:thiscall|fastcall|stdcall|cdecl|vectorcall) ?", "", sig or "")  # no calling convention
                if sig:
                    ops.append({"op": "signature", "address": subj, "signature": sig.replace(spec["edit_name"], tag)})
                rows.op("edit", lambda: c.call("edit", program=fk["key"], ops=ops))
                rows.op("decompile_edited", lambda: c.call("decompile", program=fk["key"], address=subj, timeout=120,
                                                           maxChars=10**7),
                        key="%s|fork|%s|%s" % (pname, subj, tag), hashit=decomp_hash)
                rows.op("save", lambda: c.call("save", program=fk["key"], comment="bench " + tag))
                rows.op("fork_close", lambda: c.call("close_project", project=fk["pid"], discard=True))
        rows.op("close_view", lambda: c.call("close_project", project=state["pid"]))
    finally:
        with contextlib.suppress(Exception):
            c.close()
    return 0


def cmd_subagent(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    t0 = time.perf_counter()
    gs = load_gs(spec["engine"])
    rows = Rows(spec["rows"], spec["name"])
    proj = spec["project"]
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    c = rows.op("sub_connect", lambda: d.connect(spec["name"], "bench-subagent", start=False))
    if c is None:
        return 1
    try:
        st = {}

        def open_view():
            o = c.call("open_project", path=proj["gpr"], writable=False)
            p = c.call("open_program", path=proj["program"], project=o["id"], writable=False)
            st.update(pid=o["id"], key=p["key"])
            return p
        if rows.op("sub_open_view", open_view) is None:
            return 1
        for a in spec["hot"] + spec["fresh"]:
            rows.op("sub_decompile", lambda a=a: c.call("decompile", program=st["key"], address=a, timeout=120, maxChars=10**7),
                    key="%s|view|%s" % (proj["name"], a), hashit=decomp_hash)
        rows.op("sub_read_script", lambda: c.call("script", script="BenchRead.java", args=spec["reads"], program=st["key"],
                                                  timeout=120),
                key="%s|read|%s" % (proj["name"], ",".join(spec["reads"])), hashit=lambda r: (r or {}).get("output"))
        rows.op("sub_close", lambda: c.call("close_project", project=st["pid"]))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.f.write(json.dumps({"agent": spec["name"], "op": "subagent_total", "ok": True, "t": time.time(),
                                 "ms": round((time.perf_counter() - t0) * 1000, 2)}) + "\n")
    return 0


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
    return d.connect(name, "bench-trace", start=False)


def seed_reference_sessions(engine, state):
    """Writes ref-a and ref-b (closed) through the protocol; returns their sizes and a write event id.

    The reference sessions carry no `$string` values: a string becomes a keyed id (HMAC under a per-store random key,
    PROTOCOL-3.md / TRACE-1 section 11), which differs between two daemons by design, so a reply that holds one cannot
    be part of a cross-run digest. The live session does carry strings (it is timed, not hashed)."""
    gs = load_gs(engine)
    d = gs.Daemon(engine, str(state), INSTANCE)
    c = d.connect("bench-trace-seed", "bench-trace", start=False)
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
    rows = Rows(spec["rows"], spec["name"])
    c = rows.op("trace_connect", lambda: trace_connect(spec, spec["name"]))
    if c is None:
        return 1
    stop = Path(spec["stop"])
    cpu0 = time.process_time()
    sent = accepted = rejected = dropped = 0
    try:
        o = rows.op("trace_open_live", lambda: c.trace_open(LIVE, create=True))
        if o is None:
            return 1
        cap = o["lease"]["cap"]
        i, nxt = 0, time.perf_counter()
        batch, interval = spec["batch"], spec["interval"]
        while not stop.exists():
            events = [trace_event(i + j, source="live") for j in range(batch)]
            r = rows.op("trace_append", lambda: c.trace_append(LIVE, cap, events))
            sent += batch
            if r is not None:
                accepted += r.get("accepted", 0)
                rejected += len(r.get("rejected") or [])
                dropped += r.get("dropped_budget", 0)
            i += batch
            if (i // batch) % 20 == 0:
                rows.op("trace_mark", lambda: c.trace_mark(LIVE, cap, "bench-%d" % i))
            nxt += interval
            time.sleep(max(0.0, nxt - time.perf_counter()))
        rows.op("trace_close_live", lambda: c.trace_close(LIVE, cap))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.f.write(json.dumps({"agent": spec["name"], "op": "trace_writer_total", "ok": True, "t": time.time(),
                                 "ms": 0, "sent": sent, "accepted": accepted, "rejected": rejected,
                                 "dropped_budget": dropped,
                                 "cpu_ms": round((time.process_time() - cpu0) * 1000, 1)}) + "\n")
    return 0


def cmd_tracereader(spec_path):
    """An analysis agent reading traces while the capture goes on: reference reads (hashed) and live reads."""
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    rows = Rows(spec["rows"], spec["name"])
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
            rows.op("trace_info", lambda: c.trace_info("ref-a"), tkey="trace|info|ref-a")
            rows.op("trace_query", lambda: c.trace_query("ref-a", limit=100), tkey="trace|query|ref-a")
            rows.op("trace_groups", lambda: c.trace_query("ref-a", group_by="kind"), tkey="trace|groups|ref-a")
            rows.op("trace_check", lambda: c.trace_check("ref-a", check, persist=False), tkey="trace|check|ref-a")
            if ref.get("ref-a", {}).get("write_event"):
                rows.op("trace_explain",
                        lambda: c.trace_explain("ref-a", ref["ref-a"]["write_event"], max_events=50),
                        tkey="trace|explain|ref-a")
            if n % 4 == 1:
                rows.op("trace_diff", lambda: c.trace_diff("ref-a", "ref-b", group_by="kind"),
                        tkey="trace|diff|ref-a|ref-b")
            # the live session moves: these replies are timed, not hashed
            if spec.get("live_info", True):
                rows.op("live_info", lambda: c.trace_info(LIVE))
            rows.op("live_query", lambda: c.trace_query(LIVE, limit=100))
            rows.op("live_groups", lambda: c.trace_query(LIVE, group_by="kind"))
            rows.op("live_check", lambda: c.trace_check(LIVE, check, persist=False))
            time.sleep(spec.get("pause", 0.05))
    finally:
        with contextlib.suppress(Exception):
            c.close()
        rows.f.write(json.dumps({"agent": spec["name"], "op": "trace_reader_total", "ok": True, "t": time.time(),
                                 "ms": 0, "rounds": n,
                                 "cpu_ms": round((time.process_time() - cpu0) * 1000, 1)}) + "\n")
    return 0


class LoadMon(threading.Thread):
    """System-wide busy cores from GetSystemTimes, every second (the other lanes' load is part of every run)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.samples = []            # (epoch, busy cores)
        self.stop_evt = threading.Event()

    @staticmethod
    def _times():
        i, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
        K32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
        return _ft(i), _ft(k), _ft(u)

    def run(self):
        i0, k0, u0 = self._times()
        tw = time.time()
        while not self.stop_evt.wait(1.0):
            i1, k1, u1 = self._times()
            now = time.time()
            self.samples.append((now, max(0.0, ((k1 - k0) + (u1 - u0) - (i1 - i0)) / 1e7 / max(0.001, now - tw))))
            i0, k0, u0, tw = i1, k1, u1, now

    def mean(self, t0, t1):
        xs = [b for t, b in self.samples if t0 <= t <= t1]
        return {"mean_busy_cores": round(statistics.mean(xs), 2) if xs else None,
                "max_busy_cores": round(max(xs), 2) if xs else None, "samples": len(xs)}


# ----------------------------------------------------------------------------------------------- Hydralysis side
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


def cmd_hysetup(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    settings = hy_boot(spec)
    from hydralysis import preparation
    out = {"targets": {}}
    for t in spec["targets"]:
        t0 = time.time()
        r = preparation.adopt(settings, t["gpr"], exe=t["exe"], target=t["name"])
        out["targets"][t["name"]] = {"s": round(time.time() - t0, 2), "result": {k: r.get(k) for k in ("state", "registered", "reason")}}
        if not r.get("registered", True) and r.get("state") not in (None, "registered", "done", "adopted"):
            out["error"] = r
    ask = hy_asker(settings)
    # rename subjects for the publishers: fx functions that no CALL/JUMP reaches (a rename changes no other decompile)
    fx = spec["subject_target"]
    names, cursor = {}, ""
    for _ in range(20):
        r = ask(fx, "functions", limit=200, cursor=cursor)
        for f in r.get("functions", []):
            names[f["address"]] = f["name"]
        cursor = r.get("next_cursor") or ""
        if not cursor:
            break
    free = []
    for a in sorted(names):
        if len(free) >= spec["subjects_needed"]:
            break
        x = ask(fx, "xrefs", a, limit=200)
        if not any(ref.get("type", "DATA") != "DATA" for ref in x.get("references") or []):
            free.append(a)
    out["free"] = free
    out["fx_functions"] = len(names)
    write_json(spec["out"], out)
    return 0


def cmd_hyagent(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    settings = hy_boot(spec)
    ask = hy_asker(settings)
    rows = Rows(spec["rows"], spec["name"])
    rng = random.Random(spec["seed"])
    me = spec["name"]
    rows.op("hy_functions", lambda: ask("kotor", "functions", limit=200))
    work = [("hy_decompile_hot", a) for a in spec["hot"]] + [("hy_decompile_fresh", a) for a in spec["fresh"]]
    work += [("hy_xrefs", a) for a in spec["xrefs"]]
    rng.shuffle(work)
    for op, a in work:
        if op == "hy_xrefs":
            rows.op(op, lambda a=a: ask("kotor", "xrefs", a, limit=50), key="kotor|hyxrefs|%s" % a, hashit=lambda r: r)
        else:
            rows.op(op, lambda a=a: ask("kotor", "decompile", a), key="kotor|hy|%s" % a,
                    hashit=lambda r: r)
    for n, subj in enumerate(spec["subjects"]):
        rev = lambda: ask("fx", "status", **{"as": me}).get("view_revision", 0)  # noqa: E731
        tag = "hy_%s_%d" % (me.replace("-", "_"), n)
        if rows.op("hy_edit", lambda: ask("fx", "type_edit", subj, kind="rename", name=tag, source="bench",
                                          expect_revision=rev(), **{"as": me})) is None:
            continue
        t0 = time.perf_counter()
        res = {}

        def publish():
            p = ask("fx", "type_edit", kind="publish", expect_revision=rev(), confirm_one_way_upgrade=True, **{"as": me})
            csid = p.get("csid")
            deadline = time.time() + spec.get("publish_wait_s", 300)
            while time.time() < deadline:
                q = ask("fx", "status", show="queue", csid=csid, **{"as": me})
                cs = q.get("changeset") or {}
                if cs.get("state") in ("done", "unknown"):
                    res.update(outcome=cs.get("outcome"))
                    if cs.get("outcome") not in ("applied", "rebased", "converged", "skipped"):
                        raise HyError("publish_" + str(cs.get("outcome")), json.dumps(cs)[:300])
                    return cs
                time.sleep(0.25)
            raise HyError("publish_undecided", csid)
        rows.op("hy_publish", publish)
        rows.f.write(json.dumps({"agent": me, "op": "hy_publish_outcome", "ok": bool(res), "t": time.time(),
                                 "ms": round((time.perf_counter() - t0) * 1000, 2), "outcome": res.get("outcome")}) + "\n")
    return 0


def cmd_hystop(spec_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    gs = load_gs(spec["engine"])
    d = gs.Daemon(spec["engine"], spec["state"], INSTANCE)
    with contextlib.suppress(Exception):
        if d.stop(force=True, timeout=120):
            return 0
    with contextlib.suppress(Exception):
        d.kill()
    return 0


# ----------------------------------------------------------------------------------------------- orchestrator
def run_child(args, log, timeout, env=None, python=sys.executable):
    with open(log, "ab") as lf:
        return subprocess.run([str(python), "-I", str(Path(__file__)), *args], stdout=lf, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, timeout=timeout, env=env).returncode


def spawn_child(args, log, env=None, python=sys.executable):
    lf = open(log, "ab")
    return subprocess.Popen([str(python), "-I", str(Path(__file__)), *args], stdout=lf, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, env=env), lf


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, math.ceil(q * len(xs)) - 1))] if xs else None


def strided(xs, n, offset=0):
    if not xs:
        return []
    step = max(1, len(xs) // max(1, n))
    return [xs[(offset + i * step) % len(xs)] for i in range(n)]


def cmd_run(a):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = WORK / ("%s-%s" % (a.label, stamp))
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True)
    (root / "rows").mkdir()
    (root / "specs").mkdir()
    (root / "logs").mkdir()
    (root / "forks").mkdir()
    engine = str(Path(a.engine))
    env = dict(os.environ)
    env["GHIDRA_SESSION_JAVA_HOME"] = JAVA
    env.pop("GHIDRA_SESSION_VMARGS", None)
    env.pop("HYDRA_CPU_PROFILE", None)
    os.environ.pop("HYDRA_CPU_PROFILE", None)
    if a.cpu_profile:
        env["HYDRA_CPU_PROFILE"] = a.cpu_profile
        os.environ["HYDRA_CPU_PROFILE"] = a.cpu_profile
    if a.vmargs:
        env["GHIDRA_SESSION_VMARGS"] = a.vmargs
    os.environ.pop("GHIDRA_SESSION_VMARGS", None)
    if a.vmargs:
        os.environ["GHIDRA_SESSION_VMARGS"] = a.vmargs
    res = {"label": a.label, "engine": engine, "vmargs": a.vmargs or "", "agents": a.agents, "root": str(root),
           "started": stamp, "cpus": os.cpu_count(), "phases": {}, "cpu_profile": a.cpu_profile or "",
           "trace_readers": a.trace_readers}
    loadmon = LoadMon()
    loadmon.start()
    if a.affinity:
        K32.GetCurrentProcess.restype = wt.HANDLE
        K32.SetProcessAffinityMask.argtypes = [wt.HANDLE, ctypes.c_size_t]
        if not K32.SetProcessAffinityMask(K32.GetCurrentProcess(), (1 << a.affinity) - 1):
            raise OSError("SetProcessAffinityMask failed: %s" % ctypes.get_last_error())
        res["affinity_cpus"] = a.affinity
    sampler = Sampler()
    sampler.start()
    T = {"start": time.perf_counter()}
    EPOCH = {"start": time.time()}
    c0 = sampler.cpu()

    # ---- setup: copies, Hydralysis root, adopt (starts the daemon)
    shutil.copytree(KOTOR_PROJECT, root / "kotor")
    shutil.copytree(FX_PROJECT, root / "fx")
    (root / "exe").mkdir()
    shutil.copy2(KOTOR_EXE, root / "exe" / "swkotor.exe")
    shutil.copy2(FX_EXE, root / "exe" / "diff1.exe")
    hy_root = root / "hy"
    hy_root.mkdir()
    client = Path(engine) / "Ghidra/Features/HeadlessSession/support/ghidra_session.py"
    cfg = {"root": str(hy_root / "data"), "hydra_dir": engine, "hydra_client": str(client), "hydra_idle_s": 1800,
           "java_home": JAVA, "expected_agents": max(1, min(256, a.agents))}
    if os.environ.get("BENCH_ALLOW_UNPINNED", "1") != "0":   # source-built installs carry release "dev"; both engines alike
        cfg["hydra_allow_unpinned"] = True
    if os.environ.get("BENCH_ENGINE"):  # lane A/B: engine -set entries (never JVM options, so the class cache key is the same)
        cfg["engine"] = json.loads(os.environ["BENCH_ENGINE"])
    (hy_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    scripts = hy_root / "data" / "hydra" / "user-scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(HERE / "scripts" / "BenchRead.java", scripts / "BenchRead.java")
    state = hy_root / "data" / "hydra" / "state"
    projects = {"kotor": {"name": "kotor", "gpr": str(root / "kotor" / "kotor.gpr"), "program": "/swkotor.exe"},
                "fx": {"name": "fx", "gpr": str(root / "fx" / "analysis.gpr"), "program": "/diff1.exe"}}
    n_hy = max(2, a.agents // 4) if a.agents >= 4 else 0
    n_direct = a.agents - n_hy
    hyspec = {"hy_root": str(hy_root / "data"), "hy_config": str(hy_root / "config.json"), "out": str(root / "hysetup.json"),
              "targets": [{"name": "kotor", "gpr": projects["kotor"]["gpr"], "exe": str(root / "exe" / "swkotor.exe")},
                          {"name": "fx", "gpr": projects["fx"]["gpr"], "exe": str(root / "exe" / "diff1.exe")}],
              "subject_target": "fx", "subjects_needed": max(1, n_hy * a.hy_publishes)}
    sp = root / "specs" / "hysetup.json"
    write_json(sp, hyspec)
    rc = run_child(["hysetup", str(sp)], root / "logs" / "hysetup.log", 1800, env, HY_PYTHON)
    ep = state / (INSTANCE + ".json")
    with contextlib.suppress(Exception):
        sampler.add_root(json.loads(ep.read_text(encoding="utf-8"))["pid"])
    try:
        hs = json.loads((root / "hysetup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        hs = {"error": "hysetup rc %s" % rc}
    res["hysetup"] = hs
    if rc != 0 or hs.get("error") or not ep.is_file():
        res["error"] = "setup failed (rc %s), see %s" % (rc, root / "logs" / "hysetup.log")
        print(res["error"], flush=True)
        write_json(out_dir / ("%s-%s.json" % (a.label, stamp)), res)
        stop_daemon(engine, state, root, env)
        return 1
    # the decompile sets: function lists of both programs (one direct connection)
    gs = load_gs(engine)
    d = gs.Daemon(engine, str(state), INSTANCE)
    c = d.connect("bench-setup", "bench", start=False)
    funcs = {}
    sigs = {}
    try:
        for name, pj in projects.items():
            o = c.call("open_project", path=pj["gpr"], writable=False)
            p = c.call("open_program", path=pj["program"], project=o["id"], writable=False)
            fl, off = [], 0
            while True:
                r = c.call("functions", program=p["key"], offset=off, limit=1000)
                fl += r["functions"]
                if not r.get("truncated"):
                    break
                off += r["returned"]
            funcs[name] = sorted((f["address"] for f in fl if not f.get("external") and not f.get("thunk")),
                                 key=lambda s: int(s, 16))
        # edit subjects for the direct agents (their signature for the fork's type edit), one per agent
        for name, pj in projects.items():
            subj = strided(funcs[name], a.agents, offset=3)
            o = c.call("open_project", path=pj["gpr"], writable=False)
            p = c.call("open_program", path=pj["program"], project=o["id"], writable=False)
            sigs[name] = []
            for s in subj:
                r = c.call("decompile", program=p["key"], address=s, timeout=120, maxChars=10**6)
                sigs[name].append((s, (r.get("signature") or "").rstrip(";"), r.get("name")))
            c.call("close_project", project=o["id"])
    finally:
        c.close()
    trace_ref = {}
    if a.trace_readers > 0:
        trace_ref = seed_reference_sessions(engine, state)
        res["trace_ref"] = trace_ref
    T["setup_end"] = time.perf_counter()
    EPOCH["setup_end"] = time.time()
    c1 = sampler.cpu()
    res["phases"]["setup"] = {"wall_s": round(T["setup_end"] - T["start"], 2), "cpu_s": cpu_delta(c0, c1),
                              "memory": sampler.memory(T["start"], T["setup_end"]),
                              "functions": {k: len(v) for k, v in funcs.items()}}
    print("setup", res["phases"]["setup"]["wall_s"], "s; functions", res["phases"]["setup"]["functions"], flush=True)

    # ---- workload
    hot = {k: strided(v, a.hot_set, offset=1) for k, v in funcs.items()}
    fresh_pool = {k: [x for x in strided(v, max(a.hot_set, len(v) // 2), offset=7) if x not in hot[k]] for k, v in funcs.items()}
    fresh_next = {k: 0 for k in funcs}

    def take_fresh(k, n):
        pool = fresh_pool[k]
        out = [pool[(fresh_next[k] + i) % len(pool)] for i in range(n)]
        fresh_next[k] += n
        return out
    procs = []
    free = hs.get("free") or []
    for i in range(n_direct):
        pn = "fx" if i % 3 == 2 else "kotor"
        rng = random.Random(a.seed * 1000 + i)
        s, sig, sname = sigs[pn][i % len(sigs[pn])]
        spec = {"name": "agent-%02d" % i, "engine": engine, "state": str(state), "rows": str(root / "rows" / ("agent-%02d.jsonl" % i)),
                "seed": a.seed * 1000 + i, "project": projects[pn],
                "hot": rng.sample(hot[pn], min(a.decompiles // 2, len(hot[pn]))),
                "fresh": take_fresh(pn, a.decompiles - a.decompiles // 2),
                "reads": rng.sample(funcs[pn], 8), "edit": s, "edit_sig": sig, "edit_name": sname,
                "fork": i % 2 == 0, "fork_dir": str(root / "forks" / ("agent-%02d" % i))}
        sp = root / "specs" / ("agent-%02d.json" % i)
        write_json(sp, spec)
        procs.append(("agent", sp, root / "logs" / ("agent-%02d.log" % i), sys.executable))
    for j in range(n_hy):
        rng = random.Random(a.seed * 2000 + j)
        spec = {"name": "hy-%02d" % j, "hy_root": str(hy_root / "data"), "hy_config": str(hy_root / "config.json"),
                "rows": str(root / "rows" / ("hy-%02d.jsonl" % j)), "seed": a.seed * 2000 + j,
                "hot": rng.sample(hot["kotor"], min(a.hy_decompiles // 2, len(hot["kotor"]))),
                "fresh": take_fresh("kotor", a.hy_decompiles - a.hy_decompiles // 2),
                "xrefs": rng.sample(funcs["kotor"], 4),
                "subjects": free[j * a.hy_publishes:(j + 1) * a.hy_publishes]}
        sp = root / "specs" / ("hy-%02d.json" % j)
        write_json(sp, spec)
        procs.append(("hyagent", sp, root / "logs" / ("hy-%02d.log" % j), HY_PYTHON))
    bursts = []
    for b, at in enumerate(x.strip() for x in a.burst_at.split(",") if x.strip()):
        group = []
        for k in range(a.burst_size):
            rng = random.Random(a.seed * 3000 + b * 100 + k)
            spec = {"name": "sub-%d-%02d" % (b, k), "engine": engine, "state": str(state),
                    "rows": str(root / "rows" / ("sub-%d-%02d.jsonl" % (b, k))), "project": projects["kotor"],
                    "hot": rng.sample(hot["kotor"], 3), "fresh": take_fresh("kotor", 2), "reads": rng.sample(funcs["kotor"], 2)}
            sp = root / "specs" / ("sub-%d-%02d.json" % (b, k))
            write_json(sp, spec)
            group.append(sp)
        bursts.append((at, group))
    running = []
    T["work_start"] = time.perf_counter()
    EPOCH["work_start"] = time.time()
    c2 = sampler.cpu()
    for kind, sp, log, py in procs:
        running.append(spawn_child([kind, str(sp)], log, env, py))
    trace_running = []
    stop_file = root / "stop-trace"
    if a.trace_readers > 0:
        wspec = {"name": "trace-writer", "engine": engine, "state": str(state),
                 "rows": str(root / "rows" / "trace-writer.jsonl"), "stop": str(stop_file),
                 "batch": a.trace_batch, "interval": a.trace_interval}
        sp = root / "specs" / "trace-writer.json"
        write_json(sp, wspec)
        trace_running.append(spawn_child(["tracewriter", str(sp)], root / "logs" / "trace-writer.log", env))
        for k in range(a.trace_readers):
            rspec = {"name": "trace-reader-%02d" % k, "engine": engine, "state": str(state),
                     "rows": str(root / "rows" / ("trace-reader-%02d.jsonl" % k)), "stop": str(stop_file),
                     "ref": trace_ref, "pause": a.trace_pause, "live_info": not a.trace_no_live_info}
            sp = root / "specs" / ("trace-reader-%02d.json" % k)
            write_json(sp, rspec)
            trace_running.append(spawn_child(["tracereader", str(sp)],
                                             root / "logs" / ("trace-reader-%02d.log" % k), env))
    pending = list(bursts)
    deadline = T["work_start"] + a.max_s
    while True:
        now = time.perf_counter()
        done_frac = sum(1 for p, _ in running[:len(procs)] if p.poll() is not None) / max(1, len(procs))

        def due(at):
            # "<seconds>" after the start, or "<fraction>x": once that fraction of the agent processes has exited
            return done_frac >= float(at[:-1]) if at.endswith("x") else now - T["work_start"] >= float(at)
        while pending and due(pending[0][0]):
            _, group = pending.pop(0)
            for sp in group:
                running.append(spawn_child(["subagent", str(sp)], root / "logs" / (sp.stem + ".log"), env))
        alive = [p for p, _ in running if p.poll() is None]
        if not alive and not pending:
            break
        if now > deadline:
            for p, _ in running:
                if p.poll() is None:
                    p.kill()
            res["timed_out"] = True
            break
        time.sleep(0.1)
    stop_file.write_text("stop", encoding="utf-8")
    for p, lf in trace_running:
        try:
            p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()
        lf.close()
    res["trace_exit_codes"] = [p.returncode for p, _ in trace_running]
    T["work_end"] = time.perf_counter()
    EPOCH["work_end"] = time.time()
    c3 = sampler.cpu()
    for _, lf in running:
        lf.close()
    res["exit_codes"] = [p.returncode for p, _ in running]
    with contextlib.suppress(Exception):
        res["daemon_status"] = daemon_facts(gs, engine, state)
    # ---- teardown
    stop_daemon(engine, state, root, env)
    T["end"] = time.perf_counter()
    EPOCH["end"] = time.time()
    res["epoch"] = {k: round(v, 3) for k, v in EPOCH.items()}
    time.sleep(0.5)
    c4 = sampler.cpu()
    sampler.stop_evt.set()
    sampler.join(2)
    wall = T["work_end"] - T["work_start"]
    res["phases"]["workload"] = {"wall_s": round(wall, 2), "cpu_s": cpu_delta(c2, c3),
                                 "memory": sampler.memory(T["work_start"], T["work_end"]),
                                 "load": loadmon.mean(EPOCH["work_start"], EPOCH["work_end"])}
    loadmon.stop_evt.set()
    trace = os.environ.get("BENCH_MEM_TRACE")       # measurement only: every 250 ms sample
    if trace:
        with open(trace, "w") as tf:
            for (t, total, by, detail) in sampler.samples:
                tf.write(json.dumps({"t": round(t - T["start"], 3), "mb": round(total / 2**20, 1),
                                     "by": {k: round(v / 2**20, 1) for k, v in by.items()},
                                     "top": detail}) + "\n")
    res["phases"]["teardown"] = {"wall_s": round(T["end"] - T["work_end"], 2), "cpu_s": cpu_delta(c3, c4)}
    res["phases"]["total"] = {"wall_s": round(T["end"] - T["start"], 2), "cpu_s": cpu_delta(c0, c4),
                              "memory": sampler.memory(T["start"], T["end"]), "processes": c4["processes"]}
    # ---- rows
    rows = []
    for f in sorted((root / "rows").glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            with contextlib.suppress(ValueError):
                rows.append(json.loads(line))
    ops = {}
    for r in rows:
        ops.setdefault(r["op"], []).append(r)
    res["ops"] = {}
    for op, rs in sorted(ops.items()):
        ms = [r["ms"] for r in rs if r.get("ok")]
        errs = {}
        for r in rs:
            if not r.get("ok"):
                errs[str(r.get("code"))] = errs.get(str(r.get("code")), 0) + 1
        res["ops"][op] = {"n": len(rs), "ok": len(ms), "ops_per_s": round(len(ms) / wall, 3) if wall else None,
                          "p50_ms": pct(ms, .5), "p99_ms": pct(ms, .99), "max_ms": max(ms) if ms else None,
                          "errors": errs or None}
    res["ops_total"] = {"n": len(rows), "ok": sum(1 for r in rows if r.get("ok")),
                        "errors": sum(1 for r in rows if not r.get("ok"))}
    core = [r for r in rows if not str(r["op"]).startswith(("trace_", "live_"))]
    res["ops_total_core"] = {"n": len(core), "ok": sum(1 for r in core if r.get("ok")),
                             "errors": sum(1 for r in core if not r.get("ok"))}
    hashes, inconsistent = {}, {}
    for r in rows:
        if "key" in r:
            prev = hashes.setdefault(r["key"], r["sha"])
            if prev != r["sha"]:
                inconsistent.setdefault(r["key"], sorted({prev, r["sha"]}))
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
    res["trace_agents"] = {r["agent"]: {k: r[k] for k in r if k not in ("agent", "op", "t", "ms", "ok")}
                           for r in rows if r.get("op") in ("trace_writer_total", "trace_reader_total")}
    res["correctness"] = {"keys": len(hashes), "inconsistent_in_run": inconsistent or None,
                          "digest": hashlib.sha256("\n".join("%s %s" % kv for kv in sorted(hashes.items())).encode()).hexdigest()}
    hpath = out_dir / ("%s-%s.hashes.json" % (a.label, stamp))
    write_json(hpath, hashes)
    res["hashes_file"] = str(hpath)
    path = out_dir / ("%s-%s.json" % (a.label, stamp))
    write_json(path, res)
    w = res["phases"]["workload"]
    print("workload wall %.1f s, cpu %s, mem peak %s MB mean %s MB, ops %s (%d errors), keys %d, report %s" % (
        wall, w["cpu_s"]["total"], w["memory"].get("peak_mb"), w["memory"].get("mean_mb"), res["ops_total"]["ok"],
        res["ops_total"]["errors"], len(hashes), path), flush=True)
    if not a.keep:
        shutil.rmtree(root / "forks", ignore_errors=True)
    return 0


def daemon_facts(gs, engine, state):
    d = gs.Daemon(engine, str(state), INSTANCE)
    c = d.connect("bench-facts", "bench", start=False)
    try:
        s = c.call("status")
        return {"memory": s.get("memory"), "launch": {k: (s.get("launch") or {}).get(k) for k in ("heap", "vmargs", "gc")},
                "hydraVersion": s.get("hydraVersion"), "waits": s.get("waits"), "cpu": s.get("cpu"),
                "status_keys": sorted(s)}
    finally:
        c.close()


def stop_daemon(engine, state, root, env):
    sp = root / "specs" / "hystop.json"
    write_json(sp, {"engine": engine, "state": str(state)})
    with contextlib.suppress(Exception):
        run_child(["hystop", str(sp)], root / "logs" / "hystop.log", 300, env)


# ----------------------------------------------------------------------------------------------- reports
def cmd_compare(paths):
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    hs = [json.loads(Path(r["hashes_file"]).read_text(encoding="utf-8")) for r in runs]
    base = hs[0]
    out = []
    for r, h in zip(runs[1:], hs[1:]):
        common = set(base) & set(h)
        diff = sorted(k for k in common if base[k] != h[k])
        out.append({"run": r["label"] + " " + r["started"], "common": len(common), "differ": len(diff),
                    "only_base": len(set(base) - set(h)), "only_this": len(set(h) - set(base)), "first_differ": diff[:20]})
    print(json.dumps({"base": runs[0]["label"] + " " + runs[0]["started"], "vs": out}, indent=1))
    return 0


def cmd_table(paths):
    print("| run | workload wall s | CPU s total (java / decompile / python) | peak MB | mean MB | ops ok/err | "
          "decompile p50/p99 ms | hot p50 | fresh p50 | setup wall s | setup CPU s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for p in paths:
        r = json.loads(Path(p).read_text(encoding="utf-8"))
        w = r["phases"].get("workload", {})
        cpu = w.get("cpu_s", {})
        mem = w.get("memory", {})
        ops = r.get("ops", {})
        dec = []
        for k, v in ops.items():
            if "decompile" in k:
                dec.append(v)
        d_hot, d_fresh = ops.get("decompile_hot", {}), ops.get("decompile_fresh", {})
        su = r["phases"].get("setup", {})
        print("| %s %s | %s | %s (%s / %s / %s) | %s | %s | %s/%s | %s/%s | %s | %s | %s | %s |" % (
            r["label"], r["started"][-6:], w.get("wall_s"), cpu.get("total"), cpu.get("java"), cpu.get("decompile"),
            cpu.get("python"), mem.get("peak_mb"), mem.get("mean_mb"), r.get("ops_total", {}).get("ok"),
            r.get("ops_total", {}).get("errors"), (ops.get("decompile_fresh") or {}).get("p50_ms"),
            (ops.get("decompile_fresh") or {}).get("p99_ms"), d_hot.get("p50_ms"), d_fresh.get("p50_ms"),
            su.get("wall_s"), (su.get("cpu_s") or {}).get("total")))
    return 0


def cmd_summary(paths):
    """Median per label (and the spread) of the headline figures, the per-op latency medians, and the correctness
    comparison of every run against the first run given."""
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths]
    labels = []
    for r in runs:
        if r["label"] not in labels:
            labels.append(r["label"])
    base_h = json.loads(Path(runs[0]["hashes_file"]).read_text(encoding="utf-8"))

    def med(xs):
        xs = [x for x in xs if x is not None]
        return (round(statistics.median(xs), 2), round(min(xs), 2), round(max(xs), 2)) if xs else (None, None, None)

    def fmt(t):
        return "%s (%s-%s)" % t if t[0] is not None else "-"
    print("Per configuration: median of %s runs (min-max). Workload phase only; setup (copies, adopt, daemon start) "
          "apart." % ", ".join("%s: %d" % (l, sum(1 for r in runs if r["label"] == l)) for l in labels))
    print()
    print("| metric | " + " | ".join(labels) + " |")
    print("|---|" + "---|" * len(labels))
    rowdefs = [
        ("workload wall s", lambda r: r["phases"]["workload"]["wall_s"]),
        ("CPU s total (tree, w/o bench)", lambda r: r["phases"]["workload"]["cpu_s"]["total"]),
        ("CPU s java", lambda r: r["phases"]["workload"]["cpu_s"].get("java")),
        ("CPU s decompile.exe", lambda r: r["phases"]["workload"]["cpu_s"].get("decompile")),
        ("CPU s python agents", lambda r: r["phases"]["workload"]["cpu_s"].get("python")),
        ("peak committed MB (tree)", lambda r: r["phases"]["workload"]["memory"].get("peak_mb")),
        ("mean committed MB (tree)", lambda r: r["phases"]["workload"]["memory"].get("mean_mb")),
        ("peak java private MB", lambda r: r["phases"]["workload"]["memory"].get("peak_java_mb")),
        ("ops ok", lambda r: r["ops_total"]["ok"]),
        ("op errors", lambda r: r["ops_total"]["errors"]),
        ("ops/s (all ok ops)", lambda r: round(r["ops_total"]["ok"] / r["phases"]["workload"]["wall_s"], 2)),
        ("setup wall s", lambda r: r["phases"]["setup"]["wall_s"]),
        ("setup CPU s", lambda r: r["phases"]["setup"]["cpu_s"]["total"]),
        ("total wall s (setup+workload+stop)", lambda r: r["phases"]["total"]["wall_s"]),
        ("total CPU s", lambda r: r["phases"]["total"]["cpu_s"]["total"]),
        ("total peak MB", lambda r: r["phases"]["total"]["memory"].get("peak_mb")),
    ]
    for name, fn in rowdefs:
        cells = []
        for l in labels:
            vals = []
            for r in runs:
                if r["label"] == l:
                    with contextlib.suppress(Exception):
                        vals.append(fn(r))
            cells.append(fmt(med(vals)))
        print("| %s | %s |" % (name, " | ".join(cells)))
    print()
    ops = sorted({op for r in runs for op in r.get("ops", {})})
    print("Per op type: median over runs of p50 / p99 ms, and ops/s; errors summed over runs.")
    print()
    print("| op | " + " | ".join("%s p50 / p99 ms, ops/s" % l for l in labels) + " | errors |")
    print("|---|" + "---|" * len(labels) + "---|")
    for op in ops:
        cells, errs = [], {}
        for l in labels:
            rs = [r["ops"][op] for r in runs if r["label"] == l and op in r.get("ops", {})]
            p50 = med([x["p50_ms"] for x in rs])[0]
            p99 = med([x["p99_ms"] for x in rs])[0]
            ops_s = med([x["ops_per_s"] for x in rs])[0]
            cells.append("%s / %s, %s" % (p50, p99, ops_s))
            for x in rs:
                for k, v in (x.get("errors") or {}).items():
                    errs["%s:%s" % (l, k)] = errs.get("%s:%s" % (l, k), 0) + v
        print("| %s | %s | %s |" % (op, " | ".join(cells), ", ".join("%s=%d" % kv for kv in sorted(errs.items())) or "0"))
    print()
    print("Correctness against %s %s (reply hashes per project|context|address):" % (runs[0]["label"], runs[0]["started"]))
    print()
    for r in runs:
        h = json.loads(Path(r["hashes_file"]).read_text(encoding="utf-8"))
        common = set(base_h) & set(h)
        diff = sorted(k for k in common if base_h[k] != h[k])
        errs = sorted(k for k in h if str(h[k]).startswith("ERR"))
        print("- %s %s: %d keys, %d in common, %d differ%s; %d error replies%s; in-run inconsistent: %s" % (
            r["label"], r["started"], len(h), len(common), len(diff), (" " + str(diff[:6])) if diff else "", len(errs),
            (" " + str(errs[:4])) if errs else "", (r.get("correctness") or {}).get("inconsistent_in_run")))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("agent", "subagent", "hysetup", "hyagent", "hystop", "tracewriter", "tracereader"):
        return {"agent": cmd_agent, "subagent": cmd_subagent, "hysetup": cmd_hysetup, "hyagent": cmd_hyagent,
                "hystop": cmd_hystop, "tracewriter": cmd_tracewriter, "tracereader": cmd_tracereader}[argv[0]](argv[1])
    if argv and argv[0] == "compare":
        return cmd_compare(argv[1:])
    if argv and argv[0] == "table":
        return cmd_table(argv[1:])
    if argv and argv[0] == "summary":
        return cmd_summary(argv[1:])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--engine", required=True, help="Hydra Engine install (stamped 12.3-hydra.4 for Hydralysis)")
    r.add_argument("--label", required=True)
    r.add_argument("--agents", type=int, default=16)
    r.add_argument("--vmargs", default="", help="GHIDRA_SESSION_VMARGS for the daemon (space-separated JVM options)")
    r.add_argument("--decompiles", type=int, default=40, help="decompiles per direct agent (half hot, half fresh)")
    r.add_argument("--hy-decompiles", type=int, default=12, help="decompiles per Hydralysis agent")
    r.add_argument("--hy-publishes", type=int, default=2, help="edit+publish rounds per Hydralysis agent")
    r.add_argument("--hot-set", type=int, default=24, help="size of the shared hot set per project")
    r.add_argument("--burst-at", default="5,0.5x",
                   help="when each subagent burst starts: seconds after the workload start, or <fraction>x = once that "
                        "fraction of the agent processes has exited (default: 5 s, and when half the agents are done)")
    r.add_argument("--burst-size", type=int, default=4)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--max-s", type=float, default=900, help="workload time limit; agents still running are killed")
    r.add_argument("--out", default=str(HERE / "results"))
    r.add_argument("--keep", action="store_true", help="keep the forks")
    r.add_argument("--save-replies", action="store_true", help="also write each hashed reply into the rows (diagnosis)")
    r.add_argument("--affinity", type=int, default=0, help="limit the run (and its daemon) to logical CPUs 0..N-1")
    r.add_argument("--cpu-profile", default="", help="HYDRA_CPU_PROFILE for the daemon (generic, auto, a profile name)")
    r.add_argument("--trace-readers", type=int, default=0, help="trace reader processes (>0 also starts the live capture)")
    r.add_argument("--trace-batch", type=int, default=200, help="events per trace_append of the live capture")
    r.add_argument("--trace-interval", type=float, default=0.1, help="seconds between the live capture's appends")
    r.add_argument("--trace-no-live-info", action="store_true",
                   help="readers skip trace_info on the live session (its cost grows with the session: a full-index digest)")
    r.add_argument("--trace-pause", type=float, default=0.05, help="seconds a trace reader pauses between rounds")
    a = ap.parse_args(argv)
    if a.save_replies:
        os.environ["BENCH_SAVE_REPLIES"] = "1"
    return cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
