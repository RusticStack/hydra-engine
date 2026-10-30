/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Allocator for decompile.exe on Windows.
//
// The decompiler core allocates and frees millions of small objects per function (Varnode,
// PcodeOp, and the nodes of the std::set/std::map/std::list containers that index them).
// With the default process heap that traffic goes through ntdll's heap, which a profile of the
// KotOR golden run shows as the largest single cost outside the decompiler's own code.
// This file replaces the global operator new/delete (and so every STL container's allocator)
// with mimalloc 2.2.4 (vendored, MIT, ../mimalloc), compiled here as C++, its supported
// MI_USE_CXX mode, so the native build needs no C sources.
//
// Output identity: the ordered containers that drive output compare by value (Varnode sets
// tie-break on the create index, varnode.cc; multiEntrySet is SymbolNameTree, ordered by name).
// Some maps are keyed by pointer (map<HighVariable*,...> in coreaction.cc, the type warnings map
// in type.hh, maps in subflow.cc, jumptable.cc and constseq.cc); the ones checked are used for
// lookup only, so a different address pattern does not reorder output. Identity is verified by the
// golden run (byte-identical on all 8616 KotOR functions), not guaranteed by construction.
// CRT malloc/free are left alone; nothing in the decompiler frees new-ed memory with free().
// Define HYDRA_NO_MIMALLOC to build with the CRT heap.
#if defined(_WIN32) && !defined(HYDRA_NO_MIMALLOC)
// The native build does not define NDEBUG, and without it (or this) mimalloc compiles with
// MI_DEBUG=2: internal assertions and free-list checks on every call, measured 28% slower than
// the process heap instead of faster.
#ifndef MI_BUILD_RELEASE
#define MI_BUILD_RELEASE
#endif
// Commit segment memory on demand, not a whole segment up front: with eager commit an idle
// decompile.exe holds 33 MB of private memory (2.5 MB without), once per process.
#ifndef MI_DEFAULT_EAGER_COMMIT
#define MI_DEFAULT_EAGER_COMMIT 0
#endif
// Cost of this choice: an idle decompile.exe holds about 2.5 MB private memory instead of about
// 0.6 MB with the process heap (+1.9 MB per process), against about 9% lower peak private memory
// and 13% less CPU while decompiling.
// Ignore MIMALLOC_* environment variables. decompile.exe inherits whatever environment its launcher
// has, and a variable meant for another mimalloc-using tool (MIMALLOC_EAGER_COMMIT=1,
// MIMALLOC_RESERVE_OS_MEMORY, MIMALLOC_VERBOSE, ...) would otherwise change this process's memory
// behaviour or write to stderr. The options above are then fixed at compile time.
#ifndef MI_NO_GETENV
#define MI_NO_GETENV
#endif
#include "../mimalloc/src/static.c"
#include "mimalloc-new-delete.h"
#endif

// Called by the command loop (ghidra_process.cc, when HYDRA_ALLOC_IDLE is defined) after each command
// has been answered, just before the process blocks for the next one. mimalloc purges freed pages
// lazily, from inside later allocations, so without this an idle pooled decompile.exe keeps the
// pages of its last function committed: in the multi-agent benchmark the decompile.exe processes
// held about 100 MB at the memory peak instead of about 25 MB with the process heap.
// mi_collect(true) returns them to the OS; it runs after the reply is flushed, off the latency path.
extern "C" void hydra_alloc_idle(void)
{
#if defined(_WIN32) && !defined(HYDRA_NO_MIMALLOC)
  static bool purgeSet = false;
  if (!purgeSet) {
    // Decommit freed pages as soon as they are free, not 10 ms later from inside a later allocation.
    mi_option_set(mi_option_purge_delay, 0);
    purgeSet = true;
  }
  mi_collect(true);
#endif
}
