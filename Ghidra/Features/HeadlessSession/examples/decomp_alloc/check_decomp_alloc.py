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
"""Checks the Windows decompile.exe allocator (Decompiler/src/decompile/cpp/hydra_alloc.cc). Standard library only.

    python check_decomp_alloc.py <decompile.exe | engine install>

1. mimalloc is linked (the binary carries its option names).
2. It is the release build: MI_DEBUG=0, so no "mimalloc: assertion failed" handler. The native build does not
   define NDEBUG; without MI_BUILD_RELEASE mimalloc compiles its debug checks and decompiles 28% slower.
3. An idle decompile.exe holds under 8 MB private memory: segments are committed on demand
   (MI_DEFAULT_EAGER_COMMIT 0). With eager commit it holds 33 MB from the start, in every decompiler process.
4. The process answers the pipe protocol framing: it stays alive with stdin open and exits on EOF.

Output identity is checked by the golden run (golden.py capture/diff on KotOR, 8616 functions), not here.
Exit 0 when all checks pass.
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

IDLE_PRIVATE_LIMIT_MB = 8.0


class PMC(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD)] + [(n, ctypes.c_size_t) for n in (
        "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
        "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
        "PrivateUsage")]


def private_mb(pid):
    k32 = ctypes.WinDLL("kernel32")
    k32.OpenProcess.restype = wt.HANDLE
    h = k32.OpenProcess(0x1000 | 0x0400 | 0x0010, False, pid)
    try:
        m = PMC()
        m.cb = ctypes.sizeof(PMC)
        if not ctypes.WinDLL("psapi").GetProcessMemoryInfo(h, ctypes.byref(m), m.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return m.PrivateUsage / 2.0**20
    finally:
        k32.CloseHandle(h)


def main():
    if os.name != "nt":
        print("skip: the mimalloc allocator is Windows-only")
        return 0
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    exe = os.path.abspath(sys.argv[1])
    if os.path.isdir(exe):
        exe = os.path.join(exe, "Ghidra", "Features", "Decompiler", "os", "win_x86_64", "decompile.exe")
    with open(exe, "rb") as f:
        image = f.read()
    fails = []
    if b"mimalloc" not in image:
        fails.append("mimalloc is not linked into %s" % exe)
    if b"mimalloc: assertion failed" in image:
        fails.append("mimalloc is the debug build (MI_DEBUG > 0): MI_BUILD_RELEASE/NDEBUG missing")
    p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        if p.poll() is not None:
            fails.append("decompile.exe exited (%s) with stdin still open" % p.returncode)
        else:
            mb = private_mb(p.pid)
            print("idle private memory %.1f MB (limit %.1f)" % (mb, IDLE_PRIVATE_LIMIT_MB))
            if mb >= IDLE_PRIVATE_LIMIT_MB:
                fails.append("idle decompile.exe holds %.1f MB private memory (eager segment commit?)" % mb)
        p.stdin.close()
        try:
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            fails.append("decompile.exe did not exit on stdin EOF")
    finally:
        if p.poll() is None:
            p.kill()
    for f in fails:
        print("FAIL", f)
    print("ok" if not fails else "FAILED (%d)" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
