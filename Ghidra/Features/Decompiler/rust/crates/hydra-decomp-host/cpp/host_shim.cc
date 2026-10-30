/* Hydra decompiler host shim (plan rank 12, D10).
 *
 * Runs the stock console command loop (consolemain.cc, `decomp_dbg -i script`) in-process against a
 * caller-owned output buffer. Every call builds its own IfaceStatus and, through `restore`, its own
 * Architecture; the Sleigh translator cache (SleighArchitecture::translators) and parser state are
 * thread_local, so calls on different threads share no mutable decompiler state.
 *
 * `addpath` is deliberately not registered: it appends to the process-global
 * SleighArchitecture::specpaths, which every worker reads while building an Architecture. Spec
 * search paths are fixed once by hydra_decomp_init. A script using it gets the console's
 * unknown-command error.
 *
 * No C++ exception may leave these extern "C" functions (Rust declares them `extern "C"`).
 */
#include <cstdlib>
#include <cstring>
#include <sstream>

#define main hydra_consolemain_unused_main
#include "consolemain.cc"
#undef main

namespace ghidra {
// snapshot_arch.cc: starts the library once per process for both entries (console and snapshot backend)
bool hydraLibraryStart(const char *root,std::string &err);
}

extern "C" void hydra_decomp_free(char *p) noexcept
{
  std::free(p);
}

namespace {

char *copy_out(const std::string &s, size_t *len) noexcept
{
  char *p = (char *)std::malloc(s.size() + 1);
  if (p == nullptr) { *len = 0; return nullptr; }
  std::memcpy(p, s.data(), s.size());
  p[s.size()] = 0;
  *len = s.size();
  return p;
}

}

/// Start the decompiler library once (single-threaded) and collect the .ldefs language list so
/// later, concurrent calls only read it. Returns 0 on success; on failure *err holds the reason.
extern "C" int hydra_decomp_init(const char *ghidraroot, char **err, size_t *errlen) noexcept
{
  using namespace ghidra;
  *err = nullptr; *errlen = 0;
  try {
    std::string why;
    if (!hydraLibraryStart(ghidraroot, why)) {
      *err = copy_out(why, errlen);
      return 2;
    }
    const std::vector<LanguageDescription> &d(SleighArchitecture::getDescriptions());
    if (d.empty()) {
      *err = copy_out("no .ldefs language descriptions found under the Ghidra root", errlen);
      return 1;
    }
    return 0;
  } catch (LowlevelError &e) {
    *err = copy_out(e.explain, errlen);
  } catch (std::exception &e) {
    *err = copy_out(e.what(), errlen);
  } catch (...) {
    *err = copy_out("unknown exception", errlen);
  }
  return 2;
}

/// Equivalent of `decomp_dbg -i <script> </dev/null`: *out receives exactly what the console writes
/// to stdout, *err what it writes to stderr from main. Returns the console exit code (0, 1 = a command
/// failed, 2 = interface error) or 3 for an exception the console would not have caught.
extern "C" int hydra_decomp_run_script(const char *script, char **out, size_t *outlen, char **err,
                                       size_t *errlen) noexcept
{
  using namespace ghidra;
  *out = nullptr; *outlen = 0; *err = nullptr; *errlen = 0;
  try {
  std::istringstream in;
  std::ostringstream os;
  std::ostringstream es;
  int retval = 2;
  try {
    std::unique_ptr<IfaceStatus> status(new IfaceTerm("[decomp]> ", in, os));
    IfaceCapability::registerAllCommands(status.get());
    status->registerCom(new IfcLoadFile(), "load", "file");
    status->registerCom(new IfcSave(), "save");
    status->registerCom(new IfcRestore(), "restore");
    try {
      status->pushScript(script, "init> ");
    } catch (IfaceParseError &e) {
      *status->optr << e.explain << endl;
      status->done = true;
    }
    if (!status->done)
      mainloop(status.get());
    retval = status->isInError() ? 1 : 0;
  } catch (IfaceError &e) {
    es << "Interface error: " << e.explain << endl;
    retval = 2;
  } catch (LowlevelError &e) {
    es << "LowlevelError: " << e.explain << endl;
    retval = 3;
  } catch (std::exception &e) {
    es << "exception: " << e.what() << endl;
    retval = 3;
  } catch (...) {
    es << "unknown exception" << endl;
    retval = 3;
  }
  *out = copy_out(os.str(), outlen);
  *err = copy_out(es.str(), errlen);
  return retval;
  } catch (...) {	// e.g. bad_alloc building the streams or copying them out
    hydra_decomp_free(*out);
    *out = nullptr; *outlen = 0;
    *err = nullptr; *errlen = 0;
    return 3;
  }
}

