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
// Output is unaffected: the decompiler never orders by pointer value (Varnode comparisons tie-break
// on the create index, varnode.cc), and the golden run is byte-identical with and without it.
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
#include "../mimalloc/src/static.c"
#include "mimalloc-new-delete.h"
#endif
