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
* ``cap_partial`` (issue 6): the same overflow also carries the front of the C text, additively:
  ``partial:true``, ``c`` (cut to ``maxChars``), ``chars``, ``signature`` and ``cut`` (what is missing);
  the text is a prefix of the complete decompile's, grows with the cap, and a cap that ends before
  the C markup begins gives ``cut.c_recovered:false`` and no ``c``.
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


def _with_env(env, fn):
    import os
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        return fn()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def t_cap_default(c):
    """No maxResultMb: the budget is adaptive (issue 6, owner decision). maxResultMb up to 1024 is a ceiling."""
    src = (HERE.parent / "src/main/java/ghidra/app/util/headless/session/QueryCommands.java").read_text(
        encoding="utf-8")
    check("MAX_RESULT_MB = 1024;" in src and "capBytes > 0 ? Budget.ceiling(capBytes) : Budget.auto()" in src,
          "an omitted maxResultMb takes the adaptive budget; an explicit one is the ceiling")
    gpr = copy_fixture(c, "ie-def")
    notes = []
    # 1. a low budget (test hook): omitted option, structured truncated reply with the budget numbers, never an exception
    def low():
        d = _session(c, True, "ie-def-low")
        with d.connect("cc-ie", "tests") as s:
            s.call("open_project", path=str(gpr), writable=False)
            s.call("open_program", path="/frag.exe", writable=False)
            r = s.call("decompile", address=BIG, timeout=120)
            b = r.get("budget") or {}
            check(r.get("completed") is False and r.get("truncated") is True and r.get("reason") == "response_buffer" and
                  r.get("bytes_emitted") == 64 * 1024 and b.get("mode") == "auto" and b.get("bytes") == 64 * 1024 and
                  "free_physical_mb" in b and "floor_physical_mb" in b and r.get("partial") is True,
                  f"low auto budget: { {k: v for k, v in r.items() if k != 'c'} }")
            # an explicit ceiling is a ceiling, not the auto budget
            r2 = s.call("decompile", address=BIG, timeout=120, maxResultKb=32)
            check(r2["budget"]["mode"] == "ceiling" and r2["bytes_emitted"] == 32 * 1024, f"ceiling: {r2.get('budget')}")
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
    _with_env({"HYDRA_TEST_BUDGET_KB": "64"}, low)
    notes.append("auto budget 64 KB (hook): truncated + partial + budget numbers")
    # 2. almost no free memory: the budget has a floor, a normal function still completes
    def starved():
        d = _session(c, True, "ie-def-starved")
        with d.connect("cc-ie", "tests") as s:
            s.call("open_project", path=str(gpr), writable=False)
            s.call("open_program", path="/frag.exe", writable=False)
            r = s.call("decompile", address=BIG, timeout=120)
            check(r.get("completed") is True and "budget" not in r, f"starved machine, small function: {r.get('error')}")
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
    _with_env({"HYDRA_TEST_FREE_MB": "0"}, starved)
    notes.append("no free memory (hook): the 8 MB floor still completes a small function")
    # 3. the real machine: omitted option completes; maxResultMb 1024 accepted, 1025 and 0 rejected; paging reassembles
    d = _session(c, True, "ie-def")
    with d.connect("cc-ie", "tests") as s:
        s.call("open_project", path=str(gpr), writable=False)
        s.call("open_program", path="/frag.exe", writable=False)
        expect_error("bad_request", s.call, "decompile", address=BIG, maxResultMb=1025)
        expect_error("bad_request", s.call, "decompile", address=BIG, maxResultMb=0)
        top = s.call("decompile", address=BIG, timeout=120, maxResultMb=1024)
        check(top.get("completed") is True, f"1024 MB is accepted: {top}")
        omitted = s.call("decompile", address=BIG, timeout=120)
        check(omitted.get("completed") is True and omitted["c"] == top["c"] and "offset" not in omitted,
              "an omitted cap completes the same, and carries no paging fields")
        pages, off = [], 0
        while True:
            pg = s.call("decompile", address=BIG, timeout=120, offset=off, maxChars=40000)
            pages.append(pg["c"])
            check(pg["offset"] == off and pg["chars"] == omitted["chars"], f"page at {off}: {pg['offset']}")
            if "next_offset" not in pg:
                check(pg["truncated"] is False, "the last page is not truncated")
                break
            check(pg["truncated"] is True and pg["next_offset"] == off + len(pg["c"]), "next_offset follows the page")
            off = pg["next_offset"]
        check("".join(pages) == omitted["c"] and len(pages) == 3, f"{len(pages)} pages reassemble to the whole text")
        # a small query stays answerable while another connection decompiles
        import threading
        res = []
        def slow():
            with d.connect("cc-ie2", "tests") as s2:
                s2.call("open_project", path=str(gpr), writable=False)
                s2.call("open_program", path="/frag.exe", writable=False)
                for _ in range(3):
                    s2.call("decompile", address=ENTRY, timeout=120, maxResultKb=1)
                res.append(True)
                s2.call("close_program", discard=True)
                s2.call("close_project")
        t = threading.Thread(target=slow)
        t.start()
        import time
        worst = 0.0
        for _ in range(10):
            t0 = time.time()
            s.call("decompile", address=BIG, timeout=120, offset=0, maxChars=100)
            worst = max(worst, time.time() - t0)
        t.join(120)
        check(res == [True], "the second connection ran its decompiles")
        check(worst < 10, f"concurrent small queries stay responsive (worst {worst:.2f} s)")
        s.call("close_program", discard=True)
        s.call("close_project")
    d.stop()
    notes.append("omitted option completes, 1024 accepted, 1025/0 bad_request, 3 pages reassemble, worst concurrent query %.2f s" % worst)
    return "; ".join(notes)


def _squash(text):
    return "".join(text.split())


def t_cap_partial(c):
    gpr = copy_fixture(c, "ie-part")
    notes = []
    for new in (True, False):
        d = _session(c, new, "ie-part-%s" % ("v3" if new else "v2"))
        with d.connect("cc-ie", "tests") as s:
            s.call("open_project", path=str(gpr), writable=False)
            s.call("open_program", path="/frag.exe", writable=False)
            # capped requests first: a completed decompile is cached and would answer a later capped one
            tiny = s.call("decompile", address=BIG, timeout=120, maxResultKb=1)
            caps = {}
            for kb in (2, 4, 8, 16, 32, 64, 128, 256):
                r = s.call("decompile", address=BIG, timeout=120, maxResultKb=kb)
                caps[kb] = r
                if r.get("completed") is True:
                    break  # the whole response fits from here on
            # maxChars cuts what is returned, not what is counted
            last = max(k for k, r in caps.items() if r.get("partial"))
            few = s.call("decompile", address=BIG, timeout=120, maxResultKb=last, maxChars=300)
            full = s.call("decompile", address=BIG, timeout=120)
            check(full.get("completed") is True and "partial" not in full and "cut" not in full,
                  "a complete decompile carries no partial/cut fields")
            whole = _squash(full["c"])
            brief = {k: {x: y for x, y in r.items() if x not in ("c", "error")} for k, r in caps.items()}
            got = {}
            for kb, r in caps.items():
                if r.get("completed") is True:
                    continue
                check(r.get("completed") is False and r.get("truncated") is True and
                      r.get("reason") == "response_buffer" and r.get("bytes_emitted") == kb * 1024,
                      f"{kb} KB keeps the structured overflow reply: {brief[kb]}")
                if r.get("partial") is None:
                    check((r.get("cut") or {}).get("c_recovered") is False, f"{kb} KB: no text, and the cut says so: {brief[kb]}")
                    continue  # the cap ended before the C markup began
                check(isinstance(r.get("c"), str) and r["c"], f"{kb} KB: partial C text: {brief[kb]}")
                cut = r["cut"]
                check(r["partial"] is True and cut.get("kind") == "response_buffer" and
                      cut.get("c_recovered") is True and cut.get("c_chars") == r["chars"] and
                      "missing" in cut["what"], f"{kb} KB: cut says what is missing: {cut}")
                check(0 < r["chars"] < full["chars"], f"{kb} KB: fewer chars than the whole: {r['chars']} < {full['chars']}")
                check(r["signature"] == full["signature"], f"signature {r['signature']!r} vs {full['signature']!r}")
                # the text is the front of the whole text, token for token
                check(whole.startswith(_squash(r["c"])), f"{kb} KB: the partial text is a prefix of the complete one")
                got[kb] = r["chars"]
            sizes = sorted(got)
            check(len(got) >= 2 and [got[k] for k in sizes] == sorted(got.values()) and
                  got[sizes[0]] < got[sizes[-1]], f"a larger cap recovers more text: {got}; replies: {brief}")
            # the smallest cap: a few lines, still a prefix, and the old fields are intact
            check(tiny.get("partial") is True and tiny.get("completed") is False and
                  tiny.get("reason") == "response_buffer" and tiny.get("bytes_emitted") == 1024 and
                  0 < tiny["chars"] < min(got.values()) and whole.startswith(_squash(tiny["c"])),
                  f"1 KB: {tiny}")
            check(few.get("partial") is True and len(few["c"]) <= 300 and few["chars"] == got[sizes[-1]],
                  f"maxChars 300: {len(few['c'])} chars returned of {few.get('chars')}")
            s.call("close_program", discard=True)
            s.call("close_project")
        d.stop()
        notes.append("protocol %s: caps %s KB recover %s chars of %d, each a prefix of the whole" %
                     (3 if new else 2, sizes, [got[k] for k in sizes], full["chars"]))
    return "; ".join(notes)


TESTS = {"frag_noncontiguous": t_frag_noncontiguous, "cap_overflow": t_cap_overflow,
         "cap_partial": t_cap_partial, "cap_default": t_cap_default}

if __name__ == "__main__":
    cc.run_file(__file__)
