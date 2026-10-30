# mimalloc 2.2.4 (vendored)

Unmodified `include/` and `src/` of https://github.com/microsoft/mimalloc tag `v2.2.4`
(MIT License, see `LICENSE`). Only `decompile.exe` on Windows uses it, through
`../cpp/hydra_alloc.cc`, which compiles `src/static.c` as C++ and replaces the global
`operator new`/`operator delete`. Build with `-DHYDRA_NO_MIMALLOC` to fall back to the CRT heap.

Two settings are made in `hydra_alloc.cc`, and `examples/decomp_alloc/check_decomp_alloc.py`
(HeadlessSession) checks both on a built `decompile.exe`:

- `MI_BUILD_RELEASE`: the native build does not define `NDEBUG`, and without it mimalloc
  compiles with `MI_DEBUG=2` (internal assertions on every call): 28% more decompiler CPU than
  the process heap.
- `MI_DEFAULT_EAGER_COMMIT 0`: with eager segment commit an idle `decompile.exe` holds 33 MB of
  private memory instead of 2.5 MB.

Measured 2026-10-30 on KotOR (golden explicit path, a 2000-function stratified sample, the
process-heap build and this build run side by side on the same loaded machine):
decompile.exe CPU 34.3 s -> 29.9 s (-13%), cycles 118.4 G -> 99.3 G (-16%), peak private
86.7 MB -> 78.5 MB (-9%), peak working set 88.5 MB -> 82.1 MB (-7%). Full production-path
golden (8616 functions): byte-identical to `_golden/gate1/h4/kotor/production`.
