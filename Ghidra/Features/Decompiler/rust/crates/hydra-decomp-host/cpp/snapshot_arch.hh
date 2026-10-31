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
#include <unordered_set>

namespace ghidra {

class Sleigh;			///< Native instruction translator (sleigh.hh), used by the host decode

/// \brief The answers exported for one program generation (snapshot v2 answer table)
///
/// Keys are the packed query payloads exactly as ArchitectureGhidra encodes them. An answer that
/// depends on the function being decompiled is stored under that function's \e scope (the
/// packed entry address); every other answer is global. Values are the complete response as the
/// Java side writes it (query response markers included). Entries are only ever added; readers
/// on any worker thread and the exporting thread may run concurrently.
class SnapshotStore {
  /// One part of an answer table. A lookup takes a shared lock of one shard only, so the sixteen
  /// decompiles of a generation that share a store do not serialise on one lock.
  struct Shard {
    mutable std::shared_mutex lock;
    std::unordered_map<string,string> map;
  };
  static const size_t SHARDS = 64;			///< Power of two: shard of a key is hash & (SHARDS-1)
  Shard global[SHARDS];					///< Query payload -> response
  Shard scoped[SHARDS];					///< scope + '\\0' + query payload -> response
  std::atomic<uint8> bytes;				///< Total key + value bytes held
  static size_t shardOf(const string &key);		///< Shard index of a map key
  /// Instruction starts the host decodes itself, per address space name (SnapshotStore::putDecode).
  mutable std::shared_mutex decodeLock;
  std::unordered_map<string,std::unordered_set<uintb> > decode;
  /// The instruction context of the generation: the default blob and the address ranges where it
  /// changes, as the Java side exported them (SnapshotStore::putContext). Each Architecture
  /// applies it to the worker's ContextInternal.
  string contextBlob;
  std::atomic<int4> nativeState;			///< 0 unknown, 1 native decode usable, -1 disabled
  std::atomic<uint8> nativeErrors;			///< Native decodes that fell back to the Java answer
  std::atomic<uint8> validated;				///< Instructions the validation compared
  std::atomic<uint8> mismatches;			///< Instructions whose native and Java ops differed
  static std::string nativeReason;			///< Why native decode is off (diagnostics)
public:
  const uint8 id;					///< Unique id of this store (one per generation)
  const string pspec;					///< registerProgram: the processor spec
  const string cspec;					///< registerProgram: the compiler spec
  const string tspec;					///< registerProgram: the translator spec
  const string corespec;				///< registerProgram: the core data-types
  const string options;					///< setOptions payload (packed), empty for none
  const string snapshotPath;				///< Byte snapshot file (format v1), empty for none
  const string slaPath;					///< The language's .sla file, empty for no native decode
  std::atomic<bool> closed;				///< Set when the client drops the generation
  SnapshotStore(uint8 i,const string &p,const string &c,const string &t,const string &core,
		const string &opt,const string &snap,const string &sla);
  void put(const string &scope,const string &query,const string &response);	///< Add one answer
  /// Add the answers of one packed block: for each, u32 scope length + scope, u32 query length +
  /// query, u32 response length + response (little endian). One crossing for a whole function.
  void putBulk(const char *blob,size_t len);
  /// Add native-decode records: for each, u32 name length + address space name, u32 count and
  /// count x u64 instruction offset, all little endian. One crossing for a whole function.
  void putDecode(const char *blob,size_t len);
  /// True when the host decodes the instruction at the given address itself.
  bool hasDecode(const string &space,uintb offset) const;
  /// Set the instruction context export of the generation (see SnapshotStore::contextBlob).
  void putContext(const char *blob,size_t len);
  const string &getContext(void) const { return contextBlob; }	///< The context export
  /// Mark native decode unusable for this generation and say why (first reason wins).
  void disableNative(const string &why);
  /// One native decode failed and its Java answer serves the instruction instead; the generation
  /// stops decoding natively after a few, so a systematic failure does not degrade every function.
  void nativeError(const string &why);
  void enableNative(void);				///< Record that native decode works here
  int4 getNativeState(string &why) const;		///< 1 usable, 0 not tried yet, -1 disabled
  void countValidated(void) { validated += 1; }		///< A validation comparison ran
  void countMismatch(void) { mismatches += 1; }		///< A validation comparison differed
  uint8 getValidated(void) const { return validated; }	///< Validation comparisons so far
  uint8 getMismatches(void) const { return mismatches; }	///< Validation mismatches so far
  /// Look an answer up; null when absent. The returned string stays valid while the store lives
  /// (entries are only added, and a rehash keeps the nodes). \b composite is scratch for the
  /// scoped key, reused so a lookup allocates nothing.
  const string *find(const string &scope,const string &query,string &composite) const;
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
  ///
  /// A response answered from the store is read in place (the store keeps its strings); only a
  /// speculative or exception response, made by the channel itself, is copied into \b owned.
  class InBuf : public std::streambuf {
  public:
    SnapshotChannel *owner;				///< The channel answering queries
    string owned;					///< The response when the channel made it
    void set(const char *p,size_t n) { setg((char *)p,(char *)p,(char *)p + n); }	///< Read from here
    void set(const string &s) { owned = s; set(owned.data(),owned.size()); }	///< Read a copy
    void reset(void) { owned.clear(); setg((char *)0,(char *)0,(char *)0); }	///< Drop any unread response
  protected:
    virtual int_type underflow(void);
  };
  OutBuf outbuf;					///< Backing store of \b sout
  InBuf inbuf;						///< Backing store of \b sin
  std::shared_ptr<SnapshotStore> store;			///< The answers
  string scope;						///< Scope of the current decompile (packed entry), or empty
  mutable string keybuf;				///< Scratch key of a scoped lookup
  string payload;					///< Scratch: the pending query cut from the output
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
  /// Answer the given query from the store without writing it to the output: the response (or the
  /// miss exception) is what the next read of \b sin returns. False when the store has no answer.
  bool prepare(const string &payload);
  /// The store's answer to a query, without feeding it (null when absent).
  const string *peek(const string &payload) const;
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
  Sleigh *native;					///< Native translator for this generation, or null
  bool nativePrepared;					///< The native translator serves \b this right now
  bool nativeFailed;					///< Native decode was refused for this generation
  int4 nativeWords;					///< Context words the native translator needs
  string payload;					///< Scratch: the packed p-code query of one instruction
  /// Ask the worker's native translator for this generation (loader and context set up).
  bool prepareNative(void);
  virtual Translate *buildTranslator(DocumentStorage &store);
public:
  SnapshotArchitecture(const std::shared_ptr<SnapshotStore> &st);
  ~SnapshotArchitecture(void);
  SnapshotChannel &getChannel(void) { return channel; }	///< The client streams
  bool isRegistered(void) const { return registered; }	///< True once registerHost() succeeded
  string registerHost(void);				///< registerProgram, setSnapshot and setOptions
  void decompileAt(const string &addrBytes);		///< The decompileAt command: response into the channel output
  void flushNative(void);				///< The flushNative command, as the client sends after each decompile
  /// The store's p-code answer for the instruction at \b addr, ready on the input stream; the
  /// response may be a Java exception (a read throws JavaError). False when the store has no
  /// answer: the miss is recorded and an exception is fed, as a query would.
  bool preparePcode(const Address &addr);
  /// Decode the instruction at \b addr with the native translator: its length, or -1 when the
  /// host has no native decode record for it (the caller then asks the store).
  int4 nativeDecode(PcodeEmit &emit,const Address &addr);
  Sleigh *getNative(void) const { return native; }	///< The worker's native translator, or null
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
/// Create a store for one generation; returns an opaque handle (null on failure). \b sla is the
/// language's .sla file (empty: no native decode).
void *hydra_snapshot_store_new(const char *pspec,size_t pspeclen,const char *cspec,size_t cspeclen,
			       const char *tspec,size_t tspeclen,const char *core,size_t corelen,
			       const char *opt,size_t optlen,const char *snap,size_t snaplen,
			       const char *sla,size_t slalen);
/// Add one answer (scope may be empty for a global answer); returns 0, or 1 on failure
int hydra_snapshot_store_put(void *h,const char *scope,size_t scopelen,const char *query,size_t querylen,
			     const char *resp,size_t resplen);
/// Add the answers of one packed block (see SnapshotStore::putBulk); returns 0, or 1 on failure
int hydra_snapshot_store_put_bulk(void *h,const char *blob,size_t len);
/// Add native-decode records (see SnapshotStore::putDecode); returns 0, or 1 on failure
int hydra_snapshot_store_put_decode(void *h,const char *blob,size_t len);
/// Set the generation's instruction-context export (see SnapshotStore::putContext); 0 or 1
int hydra_snapshot_store_put_context(void *h,const char *blob,size_t len);
/// 1 when native decode is usable, 0 before it was tried, -1 when disabled (the reason is returned)
int hydra_snapshot_store_native(void *h,char **msg,size_t *msglen);
/// Instructions the validation compared and how many differed (validation mode)
void hydra_snapshot_store_validate(void *h,uint64_t *checked,uint64_t *mismatched);
/// Turn the native-vs-Java p-code validation on or off (diagnostics; before any decompile)
void hydra_snapshot_set_validate(int on);
/// Prase the .sla files of these paths on every worker (warm-up); 0 on success
int hydra_snapshot_warm(const char *paths,size_t len);
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
