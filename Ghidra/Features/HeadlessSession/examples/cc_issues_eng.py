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
"""Decompile of a non-contiguous function (hydra-engine issue 7) and the per-query response cap
(hydra-engine issue 6).

    python cc_issues_eng.py --ghidra <install> --work <empty dir>

The fixture is a synthetic x64 PE whose function at 0x140001000 has a body in eight pieces: the
entry piece, six three-byte code pieces that each fall through into a table of pointers (the gap;
its first byte, 0x06, is not an instruction in 64-bit mode), and one piece that is all pointers.
A decompile of the whole body reaches six bad instructions, more than the decompiler's four, and
fails with ``Bad instruction count exceeded`` (the failure of issue 7).

* ``frag_noncontiguous`` (issue 7): the decompile succeeds, ``partial`` is true, ``fragments`` lists
  the eight pieces as ``{start, end, class, decompiled}`` with seven ``code`` pieces and one ``data``
  piece that was skipped, and a function with a contiguous body answers as before (no ``fragments``).
* ``cap_overflow`` (issue 6): ``maxResultKb`` 1 on a function whose result is larger answers
  ``completed:false, truncated:true, bytes_emitted:1024, reason:"response_buffer"`` instead of an
  error, on protocol 2 and 3; the same request without the cap, and a later one, complete (the
  decompiler is not left with the cap); ``maxResultMb`` out of range is ``bad_request``.
"""
import pathlib
import shutil
import struct

import client_compat_tests as cc
from client_compat_tests import check, expect_error

HERE = pathlib.Path(__file__).resolve().parent
IMAGE_BASE = 0x140000000
ENTRY = "0x140001000"
PIECES = 6
GAP = 0x100          # offset of the first code piece
STRIDE = 0x20
DATA_AT = 0x200      # offset of the all-pointer piece
BIG = "0x140001300"  # a contiguous function with a long body (many statements)


def make_pe() -> bytes:
    code = bytearray(b"\xCC" * 0x800)
    o = 0
    for i in range(1, PIECES + 1):
        target = GAP + STRIDE * (i - 1)
        code[o:o + 3] = bytes([0x83, 0xF9, i])                       # cmp ecx,i
        code[o + 3:o + 9] = b"\x0F\x84" + struct.pack("<i", target - (o + 9))   # je piece
        o += 9
    code[o:o + 3] = bytes([0x31, 0xC0, 0xC3])                        # xor eax,eax ; ret
    for i in range(1, PIECES + 1):
        p = GAP + STRIDE * (i - 1)
        code[p:p + 3] = bytes([0x8D, 0x41, i])                       # lea eax,[rcx+i]; falls into the table
        tab = bytearray()
        for k in range(3):
            tab += struct.pack("<Q", IMAGE_BASE + 0x1006 + 0x10 * k)  # low byte 0x06: no instruction
        tab += b"\x06" * (STRIDE - 3 - len(tab))
        code[p + 3:p + STRIDE] = tab
    for k in range(4):
        code[DATA_AT + 8 * k:DATA_AT + 8 * k + 8] = struct.pack("<Q", IMAGE_BASE + 0x1006 + 0x10 * k)
    # BIG: 2000 bytes of straight arithmetic on rcx, so its C is several KB
    b = 0x300
    for n in range(280):
        code[b:b + 4] = bytes([0x48, 0x8D, 0x49, (n * 7 + 3) & 0x7F])  # lea rcx,[rcx+imm8]
        b += 4
        code[b:b + 4] = bytes([0x48, 0x0F, 0xAF, 0xC9]) if n % 3 == 0 else bytes([0x48, 0xD1, 0xE1, 0x90])
        b += 4
    code[b:b + 4] = bytes([0x48, 0x89, 0xC8, 0xC3])                  # mov rax,rcx ; ret
    size = 0x800
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x5F000000, 0, 0, 0xF0, 0x0022)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 2, 0, size, 0, 0, 0x1000, 0x1000,
                      IMAGE_BASE, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x1000 + size, 0x200, 0, 3,
                      0x0100, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)
    sect = struct.pack("<8sIIIIIIHHI", b".text", size, 0x1000, size, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = bytes(dos) + b"PE\0\0" + coff + opt + sect
    return hdr + b"\x00" * (0x200 - len(hdr)) + bytes(code)


FIX_SCRIPT = """// @category HeadlessSession.IssuesEng
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class FragFixture extends GhidraScript {
    @Override protected void run() throws Exception {
        // the pieces are code the analysis may or may not have disassembled: make each, then the body
        AddressSet body = new AddressSet();
        body.add(toAddr(0x140001000L), toAddr(0x140001038L));
        for (int i = 0; i < 6; i++) {
            Address p = toAddr(0x140001100L + 0x20L * i);
            disassemble(p);
            body.add(p, p.add(2));
        }
        body.add(toAddr(0x140001200L), toAddr(0x14000121fL));
        Function f = getFunctionAt(toAddr(0x140001000L));
        if (f == null) {
            f = createFunction(toAddr(0x140001000L), "frag_fn");
        }
        f.setBody(body);
        Function g = getFunctionAt(toAddr(0x140001300L));
        if (g == null) {
            g = createFunction(toAddr(0x140001300L), "big_fn");
        }
        println("pieces " + f.getBody().getNumAddressRanges() + " big " + g.getBody().getNumAddresses());
    }
}
"""


def fixture(c):
    base = c.work / "ie-fixture"
    gpr = base / "Fixture.gpr"
    if not gpr.exists():
        exe = c.work / "bin" / "frag.exe"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(make_pe())
        scr = c.work / "scripts"
        scr.mkdir(parents=True, exist_ok=True)
        (scr / "FragFixture.java").write_text(FIX_SCRIPT)
        d = c.daemon("ie-fixture")
        with d.connect("fixture", "cc-ie") as s:
            c.make_project(s, base, "Fixture")
            s.call("open_project", path=str(gpr), writable=True)
            s.call("import", file=str(exe), analyze=True, timeout=600, wait=300000)
            s.call("open_program", path="/frag.exe", writable=True)
            r = s.call("script", script=str(scr / "FragFixture.java"), save=True, timeout=120)
            check("pieces 8" in str(r), f"fixture script: {r}")
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
    return base


def copy_fixture(c, name):
    dst = c.work / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(fixture(c), dst)
    return dst / "Fixture.gpr"


def _session(c, new, name):
    d = c.new_daemon(name) if new else c.daemon(name)
    return d


def t_frag_noncontiguous(c):
    gpr = copy_fixture(c, "ie-frag")
    notes = []
    for new in (True, False):
        d = _session(c, new, "ie-frag-%s" % ("v3" if new else "v2"))
        with d.connect("cc-ie", "tests") as s:
            s.call("open_project", path=str(gpr), writable=False)
            s.call("open_program", path="/frag.exe", writable=False)
            r = s.call("decompile", address=ENTRY, timeout=120)
            check(r.get("completed") is True and r.get("partial") is True and "fragments" in r,
                  f"protocol {s.hello['protocol']}: no fragment answer: { {k: v for k, v in r.items() if k != 'c'} }")
            fr = r["fragments"]
            check(len(fr) == 8, f"fragments: {fr}")
            classes = [f["class"] for f in fr]
            check(classes.count("code") == 7 and classes.count("data") == 1, f"classes: {classes}")
            data = [f for f in fr if f["class"] == "data"][0]
            check(data["start"] == "0x140001200" and data["decompiled"] is False, f"data piece: {data}")
            check(all(f["decompiled"] for f in fr if f["class"] == "code"), f"undecompiled code: {fr}")
            check(r["reason"] == "non_contiguous_body" and "fragment 0x140001000" in r["c"],
                  f"text: {r['c'][:300]}")
            # a contiguous function answers exactly as before
            g = s.call("decompile", address=BIG, timeout=120)
            check(g.get("completed") is True and "fragments" not in g and "partial" not in g,
                  f"contiguous: { {k: v for k, v in g.items() if k != 'c'} }")
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
        notes.append("protocol %s: %d fragments (%d code, 1 data)" % (3 if new else 2, len(fr), classes.count("code")))
    return "; ".join(notes)


def t_cap_overflow(c):
    gpr = copy_fixture(c, "ie-cap")
    notes = []
    for new in (True, False):
        d = _session(c, new, "ie-cap-%s" % ("v3" if new else "v2"))
        with d.connect("cc-ie", "tests") as s:
            s.call("open_project", path=str(gpr), writable=False)
            s.call("open_program", path="/frag.exe", writable=False)
            r = s.call("decompile", address=BIG, timeout=120, maxResultKb=1)
            check(r.get("completed") is False and r.get("truncated") is True and
                  r.get("bytes_emitted") == 1024 and r.get("reason") == "response_buffer" and
                  r.get("timedOut") is False, f"protocol {s.hello['protocol']} overflow: {r}")
            check("Response buffer size exceeded" in r["error"], f"error: {r}")
            # the decompiler is not left with the cap, and the overflow is not cached or shared
            ok = s.call("decompile", address=BIG, timeout=120)
            check(ok.get("completed") is True and ok.get("truncated") is False and ok["chars"] > 1000,
                  f"after the overflow: { {k: v for k, v in ok.items() if k != 'c'} }")
            big = s.call("decompile", address=BIG, timeout=120, maxResultMb=64)
            check(big.get("completed") is True, f"a raised cap: {big}")
            again = s.call("decompile", address=BIG, timeout=120, max_result_kb=1)
            check(again.get("reason") == "response_buffer" or again.get("completed") is True,
                  f"snake_case alias: {again}")
            expect_error("bad_request", s.call, "decompile", address=BIG, maxResultMb=0)
            expect_error("bad_request", s.call, "decompile", address=BIG, maxResultMb=100000)
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
        notes.append("protocol %s: 1 KB cap -> truncated, bytes_emitted 1024; uncapped completes (%d chars)" %
                     (3 if new else 2, ok["chars"]))
    return "; ".join(notes)


TESTS = {"frag_noncontiguous": t_frag_noncontiguous, "cap_overflow": t_cap_overflow}

if __name__ == "__main__":
    cc.run_file(__file__)
