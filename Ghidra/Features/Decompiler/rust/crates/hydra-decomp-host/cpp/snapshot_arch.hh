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
/// \file snapshot_arch.hh
/// \brief Hydra: an ArchitectureGhidra answered from a program generation's exported answers
///
/// The callback-free decompile backend (DESIGN.md, step 5 / step 6). A \b SnapshotStore holds,
/// for one sealed program generation, everything the Java DecompileCallback answers: the
/// registerProgram spec strings, the encoded options, the byte snapshot (format v1 file) and the
/// answer table (snapshot v2): for every query the decompiler sends, the exact response bytes the
/// Java side writes to the pipe. The Java side exports each answer once per generation.
///
/// A \b SnapshotArchitecture is the stock ArchitectureGhidra (the same Scope, TypeFactory,
/// Translate, Context, Comment and Inject components as decompile.exe) whose client streams are
/// a \b SnapshotChannel: a query written to the output stream is looked up in the store and its
/// stored response is fed to the input stream, with no Java call. A query the store does not
/// hold is a \e miss: the channel answers it with an exception (so the decompiler unwinds as it
/// does for a Java exception), records the query, and the whole result is discarded; the caller
/// exports the missed answers and runs again, or falls back to the process path.
///
/// Like XmlArchitecture / SleighArchitecture, an Architecture is thread-affine: it is built, used
/// and destroyed by one worker thread (see the host DESIGN.md, "Thread affinity").
#ifndef __SNAPSHOT_ARCH_HH__
#define __SNAPSHOT_ARCH_HH__

#include "ghidra_arch.hh"

#include <atomic>
#include <memory>
#include <shared_mutex>
#include <streambuf>
#include <unordered_map>

namespace ghidra {

/// \brief The answers exported for one program generation (snapshot v2 answer table)
///
/// Keys are the packed query payloads exactly as ArchitectureGhidra encodes them. An answer that
/// depends on the function being decompiled is stored under that function's \e scope (the
/// packed entry address); every other answer is global. Values are the complete response as the
/// Java side writes it (query response markers included). Entries are only ever added; readers
/// on any worker thread and the exporting thread may run concurrently.
class SnapshotStore {
  mutable std::shared_mutex lock;			///< Guards the two maps
  std::unordered_map<string,string> global;		///< Query payload -> response
  std::unordered_map<string,string> scoped;		///< scope + '\\0' + query payload -> response
  uint8 bytes;						///< Total key + value bytes held
public:
  const uint8 id;					///< Unique id of this store (one per generation)
  const string pspec;					///< registerProgram: the processor spec
  const string cspec;					///< registerProgram: the compiler spec
  const string tspec;					///< registerProgram: the translator spec
  const string corespec;				///< registerProgram: the core data-types
  const string options;					///< setOptions payload (packed), empty for none
  const string snapshotPath;				///< Byte snapshot file (format v1), empty for none
  std::atomic<bool> closed;				///< Set when the client drops the generation
  SnapshotStore(uint8 i,const string &p,const string &c,const string &t,const string &core,
		const string &opt,const string &snap);
  void put(const string &scope,const string &query,const string &response);	///< Add one answer
  bool find(const string &scope,const string &query,string &response) const;	///< Look an answer up
  uint8 count(void) const;				///< Number of answers held
  uint8 size(void) const;				///< Bytes held by the answers
};

/// \brief In-memory client streams for an ArchitectureGhidra, answered from a SnapshotStore
class SnapshotChannel {
  /// \brief The decompiler's output: command responses, warnings and queries
  class OutBuf : public std::streambuf {
  public:
    string data;					///< Everything written since the last reset
  protected:
    virtual int_type overflow(int_type c);
    virtual std::streamsize xsputn(const char *s,std::streamsize n);
  };
  /// \brief The client's input: the response to the last query
  class InBuf : public std::streambuf {
  public:
    SnapshotChannel *owner;				///< The channel answering queries
    string cur;						///< The response being read
    void reset(void) { cur.clear(); setg((char *)0,(char *)0,(char *)0); }	///< Drop any unread response
  protected:
    virtual int_type underflow(void);
  };
  OutBuf outbuf;					///< Backing store of \b sout
  InBuf inbuf;						///< Backing store of \b sin
  std::shared_ptr<SnapshotStore> store;			///< The answers
  string scope;						///< Scope of the current decompile (packed entry), or empty
  vector<string> misses;				///< Query payloads the store did not hold
  vector<string> fed;					///< For each miss, the neutral answer fed (empty: an exception ended the run)
  const AddrSpaceManager *spaces;			///< Address spaces for decoding a missed query (null before registration)
  bool protocolError;					///< A read with no pending query happened
  uint8 answered;					///< Queries answered from the store
  void answerNext(void);				///< Load the response to the pending query into \b inbuf
  bool speculate(const string &payload,string &resp) const;	///< Neutral answer to an optional missed query
  static const size_t MAX_SPECULATED = 256;		///< Misses a run goes on after
public:
  std::istream sin;					///< What ArchitectureGhidra reads
  std::ostream sout;					///< What ArchitectureGhidra writes
  SnapshotChannel(const std::shared_ptr<SnapshotStore> &st);
  void begin(const string &sc);				///< Start a command for the given scope
  string &output(void) { return outbuf.data; }		///< Everything written since begin()
  const vector<string> &getMisses(void) const { return misses; }	///< Queries the store did not hold
  const vector<string> &getFed(void) const { return fed; }	///< The answer fed for each miss (empty: none)
  void setSpaces(const AddrSpaceManager *s) { spaces = s; }	///< Enable decoding of missed queries
  bool hadProtocolError(void) const { return protocolError; }	///< True if a read found no query
  uint8 getAnswered(void) const { return answered; }	///< Queries answered since construction
  const std::shared_ptr<SnapshotStore> &getStore(void) const { return store; }	///< The answers
  static const char MISS_TYPE[];			///< Exception type fed back for a miss
};

/// \brief Holder for the channel, so it is built before the ArchitectureGhidra base that uses its streams
struct SnapshotChannelHolder {
  SnapshotChannel channel;				///< The client streams
  SnapshotChannelHolder(const std::shared_ptr<SnapshotStore> &st) : channel(st) {}	///< Constructor
};

/// \brief The stock ArchitectureGhidra, with the Java client replaced by a SnapshotStore
///
/// Built from the store's registerProgram strings. Every component (ScopeGhidra, TypeFactoryGhidra,
/// GhidraTranslate, ContextGhidra, CommentDatabaseGhidra, PcodeInjectLibraryGhidra,
/// ConstantPoolGhidra, GhidraStringManager, LoadImageGhidra) is the one decompile.exe uses, so the
/// decompile and its encoded result are those of the process path for the same answers.
class SnapshotArchitecture : private SnapshotChannelHolder, public ArchitectureGhidra {
  bool registered;					///< init + setSnapshot + setOptions completed
public:
  SnapshotArchitecture(const std::shared_ptr<SnapshotStore> &st);
  SnapshotChannel &getChannel(void) { return channel; }	///< The client streams
  bool isRegistered(void) const { return registered; }	///< True once registerHost() succeeded
  string registerHost(void);				///< registerProgram, setSnapshot and setOptions
  void decompileAt(const string &addrBytes);		///< The decompileAt command: response into the channel output
  void flushNative(void);				///< The flushNative command, as the client sends after each decompile
};

/// Status codes of hydra_snapshot_decompile
enum {
  SNAPSHOT_OK = 0,		///< The command response is complete; no query missed
  SNAPSHOT_MISSES = 1,		///< At least one query was not in the store: result discarded, misses returned
  SNAPSHOT_FAILED = 2,		///< Registration or the host failed for another reason (message returned)
  SNAPSHOT_CRASHED = 3		///< A hardware exception was caught; this worker's Architectures were dropped
};

} // End namespace ghidra

extern "C" {
/// Start the decompiler library for the snapshot backend (idempotent; no Sleigh root needed)
int hydra_snapshot_start(void);
/// Create a store for one generation; returns an opaque handle (null on failure)
void *hydra_snapshot_store_new(const char *pspec,size_t pspeclen,const char *cspec,size_t cspeclen,
			       const char *tspec,size_t tspeclen,const char *core,size_t corelen,
			       const char *opt,size_t optlen,const char *snap,size_t snaplen);
/// Add one answer (scope may be empty for a global answer); returns 0, or 1 on failure
int hydra_snapshot_store_put(void *h,const char *scope,size_t scopelen,const char *query,size_t querylen,
			     const char *resp,size_t resplen);
/// Number of answers and bytes held
void hydra_snapshot_store_stats(void *h,uint64_t *count,uint64_t *bytes);
/// Drop the client's handle: workers release their Architectures for it at their next job
void hydra_snapshot_store_close(void *h);
/// Decompile the function at the packed entry address on the calling (worker) thread
int hydra_snapshot_decompile(void *h,const char *addr,size_t addrlen,char **out,size_t *outlen,
			     char **misses,size_t *misseslen,uint64_t *answered);
/// Free a buffer returned by hydra_snapshot_decompile
void hydra_snapshot_free(char *p);
/// Drop every Architecture the calling worker holds (tests, shutdown)
void hydra_snapshot_release_thread(void);
}

#endif
