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
// Hydra: hardware-exception guard around one snapshot decompile job (DESIGN.md, failure isolation).
// Kept apart from snapshot_arch.cc: a function with __try may hold no C++ objects that need
// unwinding, and <windows.h> stays out of the decompiler headers.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <malloc.h>
#endif

extern "C" int hydra_snapshot_run_job(void *job);

#ifdef _WIN32
static int filter(unsigned long code)
{
  // C++ exceptions are caught inside the job; anything that reaches here is a fault
  return code == 0xE06D7363UL ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER;
}
#endif

extern "C" int hydra_snapshot_guarded(void *job)
{
#ifdef _WIN32
  unsigned long code = 0;
  __try {
    return hydra_snapshot_run_job(job);
  }
  __except(code = GetExceptionCode(), filter(code)) {
    if (code == EXCEPTION_STACK_OVERFLOW)
      _resetstkoflw();
    return 3;		// SNAPSHOT_CRASHED
  }
#else
  return hydra_snapshot_run_job(job);
#endif
}
